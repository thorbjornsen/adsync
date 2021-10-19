package adsync

import (
    "encoding/json"
    "errors"
    "io"
    "io/ioutil"
    "net/http"
    "net/url"
    "strconv"
    "strings"
    "time"
)

type AzureAuth struct {
    TokenType    string `json:"token_type"`
    ExpiresIn    int    `json:"expires_in"`
    ExtExpiresIn int    `json:"ext_expires_in"`
    AccessToken  string `json:"access_token"`
}

type AzureUsers struct {
    OdataContext  string `json:"@odata.context"`
    OdataNextLink string `json:"@odata.nextLink"`
    Value        []struct {
        OdataId           string        `json:"@odata.id"`
        BusinessPhones    []interface{} `json:"businessPhones"`
        DisplayName       string        `json:"displayName"`
        GivenName         string        `json:"givenName"`
        JobTitle          interface{}   `json:"jobTitle"`
        Mail              interface{}   `json:"mail"`
        MobilePhone       interface{}   `json:"mobilePhone"`
        OfficeLocation    interface{}   `json:"officeLocation"`
        PreferredLanguage interface{}   `json:"preferredLanguage"`
        Surname           string        `json:"surname"`
        UserPrincipalName string        `json:"userPrincipalName"`
        Id                string        `json:"id"`
    } `json:"value"`
}

type AzureGroup struct {
    OdataContext                  string        `json:"@odata.context"`
    OdataId                       string        `json:"@odata.id"`
    Id                            string        `json:"id"`
    DeletedDateTime               interface{}   `json:"deletedDateTime"`
    Classification                interface{}   `json:"classification"`
    CreatedDateTime               time.Time     `json:"createdDateTime"`
    CreationOptions               []interface{} `json:"creationOptions"`
    Description                   string        `json:"description"`
    DisplayName                   string        `json:"displayName"`
    ExpirationDateTime            time.Time     `json:"expirationDateTime"`
    GroupTypes                    []string      `json:"groupTypes"`
    IsAssignableToRole            interface{}   `json:"isAssignableToRole"`
    Mail                          string        `json:"mail"`
    MailEnabled                   bool          `json:"mailEnabled"`
    MailNickname                  string        `json:"mailNickname"`
    MembershipRule                interface{}   `json:"membershipRule"`
    MembershipRuleProcessingState interface{}   `json:"membershipRuleProcessingState"`
    OnPremisesDomainName          interface{}   `json:"onPremisesDomainName"`
    OnPremisesLastSyncDateTime    interface{}   `json:"onPremisesLastSyncDateTime"`
    OnPremisesNetBiosName         interface{}   `json:"onPremisesNetBiosName"`
    OnPremisesSamAccountName      interface{}   `json:"onPremisesSamAccountName"`
    OnPremisesSecurityIdentifier  interface{}   `json:"onPremisesSecurityIdentifier"`
    OnPremisesSyncEnabled         interface{}   `json:"onPremisesSyncEnabled"`
    PreferredDataLocation         string        `json:"preferredDataLocation"`
    PreferredLanguage             interface{}   `json:"preferredLanguage"`
    ProxyAddresses                []string      `json:"proxyAddresses"`
    RenewedDateTime               time.Time     `json:"renewedDateTime"`
    ResourceBehaviorOptions       []interface{} `json:"resourceBehaviorOptions"`
    ResourceProvisioningOptions   []interface{} `json:"resourceProvisioningOptions"`
    SecurityEnabled               bool          `json:"securityEnabled"`
    SecurityIdentifier            string        `json:"securityIdentifier"`
    Theme                         interface{}   `json:"theme"`
    Visibility                    string        `json:"visibility"`
    OnPremisesProvisioningErrors  []interface{} `json:"onPremisesProvisioningErrors"`
}

type AzureGroups struct {
    OdataContext  string `json:"@odata.context"`
    OdataNextLink string `json:"@odata.nextLink"`
    Value []AzureGroup
}

type AzureGroupMembers struct {
    OdataContext  string `json:"@odata.context"`
    OdataNextLink string `json:"@odata.nextLink"`
    Value        []struct {
        OdataType         string        `json:"@odata.type"`
        OdataId           string        `json:"@odata.id"`
        Id                string        `json:"id"`
        BusinessPhones    []interface{} `json:"businessPhones"`
        DisplayName       string        `json:"displayName"`
        GivenName         interface{}   `json:"givenName"`
        JobTitle          interface{}   `json:"jobTitle"`
        Mail              interface{}   `json:"mail"`
        MobilePhone       interface{}   `json:"mobilePhone"`
        OfficeLocation    interface{}   `json:"officeLocation"`
        PreferredLanguage interface{}   `json:"preferredLanguage"`
        Surname           interface{}   `json:"surname"`
        UserPrincipalName string        `json:"userPrincipalName"`
    } `json:"value"`
}

type Group struct {
    AzGroup     AzureGroup
    AzMembers []AzureGroupMembers
    AzNested  []AzureGroupMembers
}

type Azure struct {
    client *http.Client

    Auth    AzureAuth
    Users   AzureUsers

    // Map of id -> top level group
    Groups  map[string]Group
}

func (a *Azure) GetAuthorization() AzureError {

    logger.Info("Authorizing...")

    // Reset the authorization object
    a.Auth = AzureAuth{}

    rurl := "https://login.microsoftonline.com/" + config.Azure.TenantId + "/oauth2/v2.0/token"
    body := "client_id="+ config.Azure.ClientId + "&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default&client_secret=" + config.Azure.ClientSecret + "&grant_type=client_credentials"

    // Mask at least the client secret
    maskbody := "client_id="+ config.Azure.ClientId + "&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default&client_secret=********&grant_type=client_credentials"

    logger.Debug("Request URL: ", rurl)
    logger.Debug("Request Body: ", maskbody)

    req, err := http.NewRequest(http.MethodGet, rurl, strings.NewReader(body))

    if err != nil {
        logger.Debug("Problem creating the request: ", err)
        return AzureError{ Err: err }
    }

    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

    logger.Debug("Request: ", req)

    // Execute the request
    resp, err := a.client.Do(req)

    if err != nil {
        logger.Debug("Request returned an error: ", err)
        return AzureError{ Err: err }
    }

    defer func( Body io.ReadCloser ) {
        err := Body.Close()
        if err != nil {
            logger.Warn("Problem closing result reader: ", err)
        }
    } ( resp.Body );

    // Only accepted status is 200
    if resp.StatusCode != http.StatusOK {
        logger.Debug("Unexpected status code: ", resp.Status)
        return AzureError{ resp.Status, resp.StatusCode, errors.New("Expected " + strconv.Itoa(http.StatusOK)) }
    }

    //
    // Read/verify the returned body
    //
    auth := AzureAuth{}

    if body, err := ioutil.ReadAll( resp.Body ); err != nil {
        logger.Warn("Problem reading the result: ", err)
    } else if err = json.Unmarshal( body, &auth ); err != nil {
        logger.Warn("Problem unmarshaling the result: ", err)
        logger.Debug("Result: ", string(body))
    } else {
        logger.Debug("Result: ", string(body))
        a.Auth = auth
    }

    logger.Info("Authorization complete")

    return AzureError{}
}

func (a *Azure) GetUsers() AzureError {

    logger.Info("Fetching users from Azure")

    var url string

    if len(a.Users.OdataNextLink) == 0 {
        url = "https://graph.microsoft.com/v1.0/users"
    } else {
        url = a.Users.OdataNextLink
    }

    logger.Debug("Request URL: ", url)

    req, err := http.NewRequest(http.MethodGet, url, nil)

    if err != nil {
        logger.Debug("Problem creating the request: ", err)
        return AzureError{ Err: err }
    }

    req.Header.Set("Accept", "application/json")

    logger.Debug("Request: ", req)

    req.Header.Set("Authorization", "Bearer " + a.Auth.AccessToken)

    // Execute the request
    resp, err := a.client.Do(req)

    if err != nil {
        logger.Debug("Request returned an error: ", err)
        return AzureError{ Err: err }
    }

    defer func( Body io.ReadCloser ) {
        err := Body.Close()
        if err != nil {
            logger.Warn("Problem closing result reader: ", err)
        }
    } ( resp.Body );

    // Only accepted status is 200
    if resp.StatusCode != http.StatusOK {
        logger.Debug("Unexpected status code: ", resp.Status)
        return AzureError{ resp.Status, resp.StatusCode, errors.New("Expected " + strconv.Itoa(http.StatusOK)) }
    }

    //
    // Read/verify the returned body
    //
    users := AzureUsers{}

    if body, err := ioutil.ReadAll( resp.Body ); err != nil {
        logger.Warn("Problem reading the result: ", err)
    } else if err = json.Unmarshal( body, &users ); err != nil {
        logger.Warn("Problem unmarshaling the result: ", err)
        logger.Debug("Result: ", string(body))
    } else {
        logger.Debug("Result: ", string(body))
        a.Users = users
    }

    logger.Info("Fetched ", len(users.Value), " users from Azure")

    return AzureError{}
}

func (a *Azure) MoreUsers() bool {
    if len(a.Users.OdataNextLink) > 0 {
        return true
    } else {
        return false
    }
}

func (a *Azure) GetGroup( id string ) (AzureGroup,AzureError) {

    rurl := "https://graph.microsoft.com/v1.0/groups/" + id

    logger.Debug("Request URL: ", rurl)

    req, err := http.NewRequest(http.MethodGet, rurl, nil)

    if err != nil {
        logger.Debug("Problem creating the request: ", err)
        return AzureGroup{},AzureError{ Err: err }
    }

    logger.Debug("Request: ", req)

    req.Header.Set("Accept", "application/json")
    req.Header.Set("ConsistencyLevel", "eventual")

    logger.Debug("Request: ", req)

    req.Header.Set("Authorization", "Bearer " + a.Auth.AccessToken)

    // Execute the request
    resp, err := a.client.Do(req)

    if err != nil {
        logger.Debug("Request returned an error: ", err)
        return AzureGroup{},AzureError{ Err: err }
    }

    defer func( Body io.ReadCloser ) {
        err := Body.Close()
        if err != nil {
            logger.Warn("Problem closing result reader: ", err)
        }
    } ( resp.Body );

    // Only accepted status is 200
    if resp.StatusCode != http.StatusOK {
        logger.Debug("Unexpected status code: ", resp.Status)
        return AzureGroup{},AzureError{ resp.Status, resp.StatusCode, errors.New("Expected " + strconv.Itoa(http.StatusOK)) }
    }

    //
    // Read/verify the returned body
    //
    group := AzureGroup{}

    if body, err := ioutil.ReadAll( resp.Body ); err != nil {
        logger.Warn("Problem reading the result: ", err)
    } else if err = json.Unmarshal( body, &group ); err != nil {
        logger.Warn("Problem unmarshaling the result: ", err)
        logger.Debug("Result: ", string(body))
    } else {
        logger.Debug("Result: ", string(body))
    }

    return group,AzureError{}
}

func (a *Azure) getGroups( next string ) (AzureGroups,AzureError) {

    var rurl string

    if len(next) == 0 {
        rurl = "https://graph.microsoft.com/v1.0/groups"

        search := ""

        if len(config.Azure.GroupFilter) != 0 {
            for i, filter := range config.Azure.GroupFilter {
                filter := url.QueryEscape(filter)
                if i == 0 {
                    search = `$filter=startsWith(displayName,%27` + filter + `%27)`
                } else {
                    search += `+or+startsWith(displayName,%27` + filter +`%27)`
                }
            }
        }

        if len(search) > 0 {
            rurl += "?" + search
        }
    } else {
        rurl = next
    }

    logger.Debug("Request URL: ", rurl)

    req, err := http.NewRequest(http.MethodGet, rurl, nil)

    if err != nil {
        logger.Debug("Problem creating the request: ", err)
        return AzureGroups{},AzureError{ Err: err }
    }

    logger.Debug("Request: ", req)

    req.Header.Set("Accept", "application/json")
    req.Header.Set("ConsistencyLevel", "eventual")

    logger.Debug("Request: ", req)

    req.Header.Set("Authorization", "Bearer " + a.Auth.AccessToken)

    // Execute the request
    resp, err := a.client.Do(req)

    if err != nil {
        logger.Debug("Request returned an error: ", err)
        return AzureGroups{},AzureError{ Err: err }
    }

    defer func( Body io.ReadCloser ) {
        err := Body.Close()
        if err != nil {
            logger.Warn("Problem closing result reader: ", err)
        }
    } ( resp.Body );

    // Only accepted status is 200
    if resp.StatusCode != http.StatusOK {
        logger.Debug("Unexpected status code: ", resp.Status)
        return AzureGroups{},AzureError{ resp.Status, resp.StatusCode, errors.New("Expected " + strconv.Itoa(http.StatusOK)) }
    }

    //
    // Read/verify the returned body
    //
    groups := AzureGroups{}

    if body, err := ioutil.ReadAll( resp.Body ); err != nil {
        logger.Warn("Problem reading the result: ", err)
    } else if err = json.Unmarshal( body, &groups ); err != nil {
        logger.Warn("Problem unmarshaling the result: ", err)
        logger.Debug("Result: ", string(body))
    } else {
        logger.Debug("Result: ", string(body))
    }

    return groups,AzureError{}
}

func (a *Azure) GetGroups() AzureError {

    logger.Info("Fetching Azure groups")

    if a.Groups == nil {
        a.Groups = make(map[string]Group)
    }

    var next string

    if groups, err := a.getGroups( next ); ! err.Ok() {
        return err
    } else {
        for _, group := range groups.Value {
            a.Groups[group.Id] = Group{AzGroup: group}
        }
    }

    logger.Info("Fetched ", len(a.Groups), " Azure groups")

    return AzureError{}
}

func (a *Azure) GetAllGroups() AzureError {

    logger.Info("Fetching Azure groups")

    if a.Groups == nil {
        a.Groups = make(map[string]Group)
    }

    var next string

    for moregroups := true; moregroups; moregroups = len(next) > 0 {
        if groups, err := a.getGroups( next ); ! err.Ok() {
            return err
        } else {
            for _, group := range groups.Value {
                if _, ok := a.Groups[group.Id]; ! ok {
                    a.Groups[group.Id] = Group{AzGroup: group}
                } else {
                    // TODO Duplicate top level group found
                }
            }

            next = groups.OdataNextLink
        }
    }

    logger.Info("Fetched ", len(a.Groups), " Azure groups")

    return AzureError{}
}

func (a *Azure) getGroupMembers(id, next string) (AzureGroupMembers,AzureGroupMembers,AzureError) {

    var rurl string

    group := a.Groups[id]

    if group.AzMembers == nil {
        group.AzMembers = make([]AzureGroupMembers, 1)
    }

    if len(next) == 0 {
        rurl = "https://graph.microsoft.com/v1.0/groups/" + id + "/members"
    } else {
        rurl = next
    }

    logger.Debug("Request URL: ", rurl)

    req, err := http.NewRequest(http.MethodGet, rurl, nil)

    if err != nil {
        logger.Debug("Problem creating the request: ", err)
        return AzureGroupMembers{},AzureGroupMembers{},AzureError{ Err: err }
    }

    req.Header.Set("Accept", "application/json")
    req.Header.Set("Authorization", "Bearer " + a.Auth.AccessToken)

    // Execute the request
    resp, err := a.client.Do(req)

    if err != nil {
        logger.Debug("Request returned an error: ", err)
        return AzureGroupMembers{},AzureGroupMembers{},AzureError{ Err: err }
    }

    defer func( Body io.ReadCloser ) {
        err := Body.Close()
        if err != nil {
            logger.Warn("Problem closing result reader: ", err)
        }
    } ( resp.Body );

    // Only accepted status is 200
    if resp.StatusCode != http.StatusOK {
        logger.Debug("Unexpected status code: ", resp.Status)
        return AzureGroupMembers{},AzureGroupMembers{},AzureError{ resp.Status, resp.StatusCode, errors.New("Expected " + strconv.Itoa(http.StatusOK)) }
    }

    //
    // Read/verify the returned body
    //
    members := AzureGroupMembers{}
    groups := AzureGroupMembers{}

    if body, err := ioutil.ReadAll( resp.Body ); err != nil {
        logger.Warn("Problem reading the result: ", err)
    } else if err = json.Unmarshal( body, &members ); err != nil {
        logger.Warn("Problem unmarshaling the result: ", err)
        logger.Debug("Result: ", string(body))
    } else {
        logger.Debug("Result: ", string(body))
    }

    //
    // Check for nested group(s) hiding among the members
    //

    // Make a copy of the member array
    check := members.Value

    // Clear the member array
    members.Value = members.Value[:0]

    // Check the members for any groups
    for _, member := range check {
        if member.OdataType == "#microsoft.graph.user" {
            members.Value = append( members.Value, member )
        } else if member.OdataType == "#microsoft.graph.group" {
            groups.Value = append( groups.Value, member )
        } else {
            logger.Warn( "Found unsupported OdataType in group ", group.AzGroup.DisplayName )
        }
    }

    return members,groups,AzureError{}
}

func (a *Azure) GetGroupMembers(id string) AzureError {

    if _, ok := a.Groups[id]; ! ok {
        return AzureError{ Err: errors.New("Cannot fetch group members for group " + id + ", the group was not already fetched" ) }
    }

    group := a.Groups[id]

    logger.Info("Fetching Azure group members for: ", group.AzGroup.DisplayName)

    if group.AzMembers != nil && len(group.AzMembers) > 0 {
        group.AzMembers = group.AzMembers[:0]
    }
    if group.AzNested != nil && len(group.AzNested) > 0 {
        group.AzNested = group.AzNested[:0]
    }

    var next string

    if members, groups, err := a.getGroupMembers(id, next); ! err.Ok() {
        return err
    } else {
        group.AzMembers = append( group.AzMembers, members )
        group.AzNested  = append( group.AzNested,  groups  )

        a.Groups[id] = group

        if len(members.Value) > 0 {
            logger.Info("Fetched ", len(members.Value), " Azure group members for: ", group.AzGroup.DisplayName)
        }
        if len(groups.Value) > 0 {
            logger.Info("Fetched ", len(groups.Value), " Azure nested groups for: ", group.AzGroup.DisplayName)
        }
    }

    return AzureError{}
}

func (a *Azure) GetAllGroupMembers(id string) AzureError {

    if _, ok := a.Groups[id]; ! ok {
        return AzureError{ Err: errors.New("Cannot fetch group members for group " + id + ", the group was not already fetched" ) }
    }

    group := a.Groups[id]

    logger.Info("Fetching Azure group members for: ", group.AzGroup.DisplayName)

    if group.AzMembers != nil && len(group.AzMembers) > 0 {
        group.AzMembers = group.AzMembers[:0]
    }
    if group.AzNested != nil && len(group.AzNested) > 0 {
        group.AzNested = group.AzNested[:0]
    }

    var next string

    for moremembers := true; moremembers; moremembers = len(next) > 0 {
        if members, groups, err := a.getGroupMembers(id, next); ! err.Ok() {
            return err
        } else {
            group.AzMembers = append( group.AzMembers, members )
            group.AzNested  = append( group.AzNested,  groups  )

            a.Groups[id] = group

            if len(members.Value) > 0 {
                logger.Info("Fetched ", len(members.Value), " Azure group members for: ", group.AzGroup.DisplayName)
            }
            if len(groups.Value) > 0 {
                logger.Info("Fetched ", len(groups.Value), " Azure nested groups for: ", group.AzGroup.DisplayName)
            }

            next = members.OdataNextLink
        }
    }

    return AzureError{}
}


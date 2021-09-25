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

type Azure struct {
    client *http.Client

    Auth    AzureAuth
    Users   AzureUsers
    Groups  []AzureGroups
    Members []AzureGroupMembers
    Nested  []AzureGroupMembers
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

func (a *Azure) getGroups() (AzureGroups,AzureError) {

    var rurl string

    if a.Groups == nil {
        a.Groups = make([]AzureGroups, 1)
    }

    if len(a.Groups) == 0 || len(a.Groups[len(a.Groups)-1].OdataNextLink) == 0 {
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
        rurl = a.Groups[len(a.Groups)-1].OdataNextLink
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
        a.Groups = make([]AzureGroups, 5)
    }

    if groups, err := a.getGroups(); ! err.Ok() {
        return err
    } else {
        a.Groups = append( a.Groups, groups )
    }

    logger.Info("Fetched ", len(a.Groups[len(a.Groups)-1].Value), " Azure groups")

    return AzureError{}
}

func (a *Azure) GetAllGroups() AzureError {

    logger.Info("Fetching Azure groups")

    if a.Groups == nil {
        a.Groups = make([]AzureGroups, 5)
    }

    for moregroups := true; moregroups; moregroups = a.MoreGroups() {
        if groups, err := a.getGroups(); ! err.Ok() {
            return err
        } else {
            a.Groups = append( a.Groups, groups )
        }
    }

    logger.Info("Fetched ", len(a.Groups[len(a.Groups)-1].Value), " Azure groups")

    return AzureError{}
}

func (a *Azure) MoreGroups() bool {
    if a.Groups == nil {
        return false
    }

    if len(a.Groups[len(a.Groups)-1].OdataNextLink) > 0 {
        return true
    } else {
        return false
    }
}

func (a *Azure) getGroupMembers(id, name string) (AzureGroupMembers,AzureGroupMembers,AzureError) {

    var rurl string

    if a.Members == nil {
        a.Members = make([]AzureGroupMembers, 1)
    }

    if len(a.Members) == 0 || len(a.Members[len(a.Members)-1].OdataNextLink) == 0 {
        rurl = "https://graph.microsoft.com/v1.0/groups/" + id + "/members"
    } else {
        rurl = a.Members[len(a.Members)-1].OdataNextLink
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
            logger.Warn( "Found unsupported OdataType in group ", name )
        }
    }

    return members,groups,AzureError{}
}

func (a *Azure) GetGroupMembers(id, name string) AzureError {

    logger.Info("Fetching Azure group members for: ", name)

    if a.Members != nil && len(a.Members) != 0 {
        a.Members = a.Members[:0]
    }
    if a.Nested != nil && len(a.Nested) != 0 {
        a.Nested = a.Nested[:0]
    }

    if members, groups, err := a.getGroupMembers(id, name); ! err.Ok() {
        return err
    } else {
        a.Members = append( a.Members, members )
        a.Nested  = append( a.Nested,  groups  )

        if len(members.Value) > 0 {
            logger.Info("Fetched ", len(members.Value), " Azure group members for: ", name)
        }
        if len(groups.Value) > 0 {
            logger.Info("Fetched ", len(groups.Value), " Azure nested groups for: ", name)
        }
    }

    return AzureError{}
}

func (a *Azure) GetAllGroupMembers(id, name string) AzureError {

    logger.Info("Fetching Azure group members for: ", name)

    if a.Members != nil && len(a.Members) != 0 {
        a.Members = a.Members[:0]
    }
    if a.Nested != nil && len(a.Nested) != 0 {
        a.Nested = a.Nested[:0]
    }

    for moremembers := true; moremembers; moremembers = a.MoreMembers() {
        if members, groups, err := a.getGroupMembers(id, name); ! err.Ok() {
            return err
        } else {
            a.Members = append( a.Members, members )
            a.Nested  = append( a.Nested,  groups  )

            if len(members.Value) > 0 {
                logger.Info("Fetched ", len(members.Value), " Azure group members for: ", name)
            }
            if len(groups.Value) > 0 {
                logger.Info("Fetched ", len(groups.Value), " Azure nested groups for: ", name)
            }
        }
    }

    return AzureError{}
}

func (a *Azure) MoreMembers() bool {
    if a.Members == nil {
        return false
    }

    if len(a.Members[len(a.Members)-1].OdataNextLink) > 0 {
        return true
    } else {
        return false
    }
}


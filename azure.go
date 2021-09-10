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

type AzureGroups struct {
    OdataContext  string `json:"@odata.context"`
    OdataNextLink string `json:"@odata.nextLink"`
    Value        []struct {
        OdataId                       string        `json:"@odata.id"`
        Id                            string        `json:"id"`
        DeletedDateTime               interface{}   `json:"deletedDateTime"`
        Classification                interface{}   `json:"classification"`
        CreatedDateTime               time.Time     `json:"createdDateTime"`
        CreationOptions               []interface{} `json:"creationOptions"`
        Description                   string        `json:"description"`
        DisplayName                   string        `json:"displayName"`
        ExpirationDateTime            interface{}   `json:"expirationDateTime"`
        GroupTypes                    []interface{} `json:"groupTypes"`
        IsAssignableToRole            interface{}   `json:"isAssignableToRole"`
        Mail                          interface{}   `json:"mail"`
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
        PreferredDataLocation         interface{}   `json:"preferredDataLocation"`
        PreferredLanguage             interface{}   `json:"preferredLanguage"`
        ProxyAddresses                []interface{} `json:"proxyAddresses"`
        RenewedDateTime               time.Time     `json:"renewedDateTime"`
        ResourceBehaviorOptions       []interface{} `json:"resourceBehaviorOptions"`
        ResourceProvisioningOptions   []interface{} `json:"resourceProvisioningOptions"`
        SecurityEnabled               bool          `json:"securityEnabled"`
        SecurityIdentifier            string        `json:"securityIdentifier"`
        Theme                         interface{}   `json:"theme"`
        Visibility                    interface{}   `json:"visibility"`
        OnPremisesProvisioningErrors  []interface{} `json:"onPremisesProvisioningErrors"`
    } `json:"value"`
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
    Groups  AzureGroups
    Members AzureGroupMembers

    UserCount   int
    GroupCount  int
    MemberCount map[string]int
}

func (a *Azure) GetAuthorization() AzureError {

    logger.Info("Authorizing...")

    // Reset the authorization object
    a.Auth = AzureAuth{}

    url := "https://login.microsoftonline.com/" + config.Azure.TenantId + "/oauth2/v2.0/token"
    body := "client_id="+ config.Azure.ClientId + "&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default&client_secret=" + config.Azure.ClientSecret + "&grant_type=client_credentials"

    // Mask at least the client secret
    maskbody := "client_id="+ config.Azure.ClientId + "&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default&client_secret=********&grant_type=client_credentials"

    logger.Debug("Request URL: ", url)
    logger.Debug("Request Body: ", maskbody)

    req, err := http.NewRequest(http.MethodGet, url, strings.NewReader(body))

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

func (a *Azure) GetGroups() AzureError {

    logger.Info("Fetching groups from Azure")

    var rurl string

    if len(a.Groups.OdataNextLink) == 0 {
        rurl = "https://graph.microsoft.com/v1.0/groups"

        search := ""

        if len(config.Azure.GroupFilter) != 0 {
            // Constructing filter that will match the start of group displayNames (i.e. prefix)
            // "filter" should be used instead of search to leverage "startsWith" operators joined by "or" condition: https://docs.microsoft.com/en-us/graph/query-parameters#filter-parameter
            // "startsWith" is supported with "displayName": https://docs.microsoft.com/en-us/graph/aad-advanced-queries#group-properties
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
        rurl = a.Groups.OdataNextLink
    }

    logger.Debug("Request URL: ", rurl)

    req, err := http.NewRequest(http.MethodGet, rurl, nil)

    if err != nil {
        logger.Debug("Problem creating the request: ", err)
        return AzureError{ Err: err }
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
    groups := AzureGroups{}

    if body, err := ioutil.ReadAll( resp.Body ); err != nil {
        logger.Warn("Problem reading the result: ", err)
    } else if err = json.Unmarshal( body, &groups ); err != nil {
        logger.Warn("Problem unmarshaling the result: ", err)
        logger.Debug("Result: ", string(body))
    } else {
        logger.Debug("Result: ", string(body))
        a.Groups = groups
    }

    logger.Info("Fetched ", len(groups.Value), " groups from Azure")

    return AzureError{}
}

func (a *Azure) MoreGroups() bool {
    if len(a.Groups.OdataNextLink) > 0 {
        return true
    } else {
        return false
    }
}

func (a *Azure) GetGroupMembers(id, displayName string) AzureError {

    logger.Info("Fetching group members from Azure for: ", displayName)

    var url string

    if len(a.Members.OdataNextLink) == 0 {
        url = "https://graph.microsoft.com/v1.0/groups/" + id + "/members"
    } else {
        url = a.Members.OdataNextLink
    }

    logger.Debug("Request URL: ", url)

    req, err := http.NewRequest(http.MethodGet, url, nil)

    if err != nil {
        logger.Debug("Problem creating the request: ", err)
        return AzureError{ Err: err }
    }

    req.Header.Set("Accept", "application/json")
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
    members := AzureGroupMembers{}

    if body, err := ioutil.ReadAll( resp.Body ); err != nil {
        logger.Warn("Problem reading the result: ", err)
    } else if err = json.Unmarshal( body, &members ); err != nil {
        logger.Warn("Problem unmarshaling the result: ", err)
        logger.Debug("Result: ", string(body))
    } else {
        logger.Debug("Result: ", string(body))
        a.Members = members
    }

    logger.Info("Fetched ", len(members.Value), " group members from Azure for: ", displayName)

    return AzureError{}
}

func (a *Azure) MoreMembers() bool {
    if len(a.Members.OdataNextLink) > 0 {
        return true
    } else {
        return false
    }
}


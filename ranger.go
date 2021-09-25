package adsync

import (
    "bytes"
    "encoding/json"
    "errors"
    "io"
    "io/ioutil"
    "net/http"
    "strconv"
    "time"
)
//
// /service/users/default
//
type VXPortalUser struct {
    LoginId      string  `json:"loginId"`
    EmailAddress string  `json:"emailAddress"`
    FirstName    string  `json:"firstName"`
    LastName     string  `json:"lastName"`
    UserSource   uint    `json:"userSource"`
    Id           uint    `json:"id"`
}
//
// /service/xusers/users/userinfo
//
type VXUserGroupInfo struct {
    XuserInfo struct {
        Name          string   `json:"name"`
        Description   string   `json:"description"`
        GroupNameList []string `json:"groupNameList"`
        UserRoleList  []string `json:"userRoleList"`
    } `json:"xuserInfo"`
    XgroupInfo []struct {
        Name          string   `json:"name"`
        Description   string   `json:"description"`
    } `json:"xgroupInfo"`
}
//
// /service/xusers/groups
//
type VXGroup []struct {
    Name        string `json:"name"`
    Description string `json:"description"`
    GroupType   int    `json:"groupType"`
    CredStoreId int    `json:"credStoreId"`
    IsVisible   int    `json:"isVisible"`
    MyClassType int    `json:"myClassType"`
    GroupSource int    `json:"groupSource"`
    Id          int    `json:"id"`
    CreateDate  time.Time `json:"createDate"`
    UpdateDate  time.Time `json:"updateDate"`
    Owner       string `json:"owner"`
    UpdatedBy   string `json:"updatedBy"`
}

type VXGroups struct {
    VXGroups []struct {
        Name        string `json:"name"`
        Description string `json:"description"`
        GroupType   int    `json:"groupType"`
        CredStoreId int    `json:"credStoreId"`
        IsVisible   int    `json:"isVisible"`
        MyClassType int    `json:"myClassType"`
        GroupSource int    `json:"groupSource"`
        Id          int    `json:"id"`
        CreateDate  time.Time `json:"createDate"`
        UpdateDate  time.Time `json:"updateDate"`
        Owner       string `json:"owner"`
        UpdatedBy   string `json:"updatedBy"`
    } `json:"vXGroups"`
    ListSize int `json:"listSize"`
    List     []struct {
    } `json:"list"`
    StartIndex int    `json:"startIndex"`
    PageSize   int    `json:"pageSize"`
    TotalCount int    `json:"totalCount"`
    ResultSize int    `json:"resultSize"`
    SortType   string `json:"sortType"`
    SortBy     string `json:"sortBy"`
}
//
// /service/xusers/groupusers/groupName/{group}
// /service/xusers/groups/groupinfo
//
type VXGroupUserInfo struct {
    CreateDate time.Time `json:"createDate"`
    UpdateDate time.Time `json:"updateDate"`
    XgroupInfo struct {
        Id          int       `json:"id"`
        CreateDate  time.Time `json:"createDate"`
        UpdateDate  time.Time `json:"updateDate"`
        Owner       string    `json:"owner"`
        UpdatedBy   string    `json:"updatedBy"`
        Name        string    `json:"name"`
        Description string    `json:"description"`
        GroupType   int       `json:"groupType"`
        GroupSource int       `json:"groupSource"`
        IsVisible   int       `json:"isVisible"`
    } `json:"xgroupInfo"`
    XuserInfo []struct {
        CreateDate    time.Time `json:"createDate"`
        UpdateDate    time.Time `json:"updateDate"`
        Name          string    `json:"name"`
        Status        int       `json:"status"`
        IsVisible     int       `json:"isVisible"`
        UserSource    int       `json:"userSource"`
        GroupNameList []string  `json:"groupNameList"`
        UserRoleList  []string  `json:"userRoleList"`
    } `json:"xuserInfo"`
}
//
// /service/xusers/ugsync/auditinfo
//
type VXUgsyncAuditInfo struct {
    NoOfNewUsers       int    `json:"noOfNewUsers"`
    NoOfNewGroups      int    `json:"noOfNewGroups"`
    NoOfModifiedUsers  int    `json:"noOfModifiedUsers"`
    NoOfModifiedGroups int    `json:"noOfModifiedGroups"`
    SyncSource         string `json:"syncSource"`
    LdapSyncSourceInfo struct {
        LdapUrl                 string `json:"ldapUrl"`
        IncrementalSycn         string `json:"incrementalSycn"`
        GroupSearchFirstEnabled string `json:"groupSearchFirstEnabled"`
        GroupSearchEnabled      string `json:"groupSearchEnabled"`
        UserSearchEnabled       string `json:"userSearchEnabled"`
        UserSearchFilter        string `json:"userSearchFilter"`
        GroupSearchFilter       string `json:"groupSearchFilter"`
        GroupHierarchyLevel     string `json:"groupHierarchyLevel"`
        TotalUsersSynced        int    `json:"totalUsersSynced"`
        TotalGroupsSynced       int    `json:"totalGroupsSynced"`
    } `json:"ldapSyncSourceInfo"`
}

func CreatePortalUser( client *http.Client, user VXPortalUser ) RangerError {

    logger.Info("Creating Ranger portal user for: ", user.LoginId)

    // Marshal the JSON for the portal user
    portal, err := json.Marshal( user )

    if err != nil {
        logger.Debug("Problem marshaling the object: ", err)
        return RangerError{ Err: err }
    }

    url := config.Ranger.Host + config.Ranger.CreateUserUri

    logger.Debug("Request URL: ", url)
    logger.Debug("Request Body: ", string(portal))

    // Create the POST request for the Ranger create API
    req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(portal))

    if err != nil {
        logger.Debug("Problem creating the request: ", err)
        return RangerError{ Err: err }
    }

    // Add any user-supplied headers
    for key, value := range config.Ranger.Headers {
        req.Header.Set( key, value )
    }

    // Work with JSON, Ranger API defaults to XML
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Accept", "application/json")

    logger.Debug("Request: ", req)

    // Check if authorization creds have been configured
    if len(config.Ranger.User) != 0 && len(config.Ranger.Pass) != 0 {
        // Need to add authorization
        req.SetBasicAuth(config.Ranger.User, config.Ranger.Pass)
    }

    // Execute the request
    resp, err := client.Do(req)

    if err != nil {
        logger.Debug("Request returned an error: ", err)
        return RangerError{ Err: err }
    }

    defer func( Body io.ReadCloser ) {
        err := Body.Close()
        if err != nil {
            logger.Warn("Problem closing result reader: ", err)
        }
    } ( resp.Body );

    // Only accepted status is 200, even if user already existed
    if resp.StatusCode != http.StatusOK {
        logger.Debug("Unexpected status code: ", resp.Status)
        return RangerError{ resp.Status, resp.StatusCode, errors.New("Expected " + strconv.Itoa(http.StatusOK)) }
    }

    //
    // Read/verify the returned body, even though we dont need it
    //
    if body, err := ioutil.ReadAll( resp.Body ); err != nil {
        logger.Warn("Problem reading the result: ", err)
    } else if err = json.Unmarshal( body, &user ); err != nil {
        logger.Warn("Problem unmarshaling the result: ", err)
        logger.Debug("Result: ", string(body))
    } else {
        logger.Debug("Result: ", string(body))
    }

    logger.Info("Created Ranger portal user: ", user.LoginId)

    return RangerError{}
}

func CreateUserInfo( client *http.Client, uginfo VXUserGroupInfo ) RangerError {

    logger.Info("Creating Ranger user info for user: ", uginfo.XuserInfo.Name)

    // Marshal the JSON for the user info
    info, err := json.Marshal( uginfo )

    if err != nil {
        logger.Debug("Problem marshaling the object: ", err)
        return RangerError{ Err: err }
    }

    url := config.Ranger.Host + config.Ranger.UserInfoUri

    logger.Debug("Request URL: ", url)
    logger.Debug("Request Body: ", string(info))

    // Create the POST request for the Ranger create API
    req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(info))

    if err != nil {
        logger.Debug("Problem creating the request: ", err)
        return RangerError{ Err: err }
    }

    // Add any user-supplied headers
    for key, value := range config.Ranger.Headers {
        req.Header.Set( key, value )
    }

    // Work with JSON, Ranger API defaults to XML
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Accept", "application/json")

    logger.Debug("Request: ", req)

    // Check if authorization creds have been configured
    if len(config.Ranger.User) != 0 && len(config.Ranger.Pass) != 0 {
        // Need to add authorization
        req.SetBasicAuth(config.Ranger.User, config.Ranger.Pass)
    }

    // Execute the request
    resp, err := client.Do(req)

    if err != nil {
        logger.Debug("Request returned an error: ", err)
        return RangerError{ Err: err }
    }

    defer func( Body io.ReadCloser ) {
        err := Body.Close()
        if err != nil {
            logger.Warn("Problem closing result reader: ", err)
        }
    } ( resp.Body );

    // Only accepted status is 200, even if user already existed
    if resp.StatusCode != http.StatusOK {
        logger.Debug("Unexpected status code: ", resp.Status)
        return RangerError{ resp.Status, resp.StatusCode, errors.New("Expected " + strconv.Itoa(http.StatusOK)) }
    }

    //
    // Read/verify the returned body, even though we dont need it
    //
    if body, err := ioutil.ReadAll( resp.Body ); err != nil {
        logger.Warn("Problem reading the result: ", err)
    } else if err = json.Unmarshal( body, &uginfo ); err != nil {
        logger.Warn("Problem unmarshaling the result: ", err)
        logger.Debug("Result: ", string(body))
    } else {
        logger.Debug("Result: ", string(body))
    }

    logger.Info("Created Ranger user info for: ", uginfo.XuserInfo.Name)

    return RangerError{}
}

func DeleteUser( client *http.Client, id int ) RangerError {
    logger.Info("Deleting Ranger group ", id)

    url := config.Ranger.Host + config.Ranger.GroupsUri + strconv.Itoa( id )

    logger.Debug("Request URL: ", url)

    // Create the GET request for the Ranger Groups API
    req, err := http.NewRequest(http.MethodDelete, url, nil)

    if err != nil {
        logger.Debug("Problem creating the request: ", err)
        return RangerError{ Err: err }
    }

    // Add any user-supplied headers
    for key, value := range config.Ranger.Headers {
        req.Header.Set( key, value )
    }

    logger.Debug("Request: ", req)

    // Check if authorization creds have been configured
    if len(config.Ranger.User) != 0 && len(config.Ranger.Pass) != 0 {
        // Need to add authorization
        req.SetBasicAuth(config.Ranger.User, config.Ranger.Pass)
    }

    // Execute the request
    resp, err := client.Do(req)

    if err != nil {
        logger.Debug("Request returned an error: ", err)
        return RangerError{ Err: err }
    }

    // Only accepted status is 204
    if resp.StatusCode != http.StatusNoContent {
        logger.Debug("Unexpected status code: ", resp.Status)
        return RangerError{ resp.Status, resp.StatusCode, errors.New("Expected " + strconv.Itoa(http.StatusNoContent)) }
    }

    logger.Info("Deleted Ranger group", id)

    return RangerError{}
}

func GetGroups( client *http.Client ) (VXGroups,RangerError) {
    logger.Info("Fetching Ranger groups")

    url := config.Ranger.Host + config.Ranger.GroupsUri

    logger.Debug("Request URL: ", url)

    // Create the GET request for the Ranger Groups API
    req, err := http.NewRequest(http.MethodGet, url, nil)

    if err != nil {
        logger.Debug("Problem creating the request: ", err)
        return VXGroups{}, RangerError{ Err: err }
    }

    // Add any user-supplied headers
    for key, value := range config.Ranger.Headers {
        req.Header.Set( key, value )
    }

    // Work with JSON, Ranger API defaults to XML
    req.Header.Set("Accept", "application/json")

    logger.Debug("Request: ", req)

    // Check if authorization creds have been configured
    if len(config.Ranger.User) != 0 && len(config.Ranger.Pass) != 0 {
        // Need to add authorization
        req.SetBasicAuth(config.Ranger.User, config.Ranger.Pass)
    }

    // Execute the request
    resp, err := client.Do(req)

    if err != nil {
        logger.Debug("Request returned an error: ", err)
        return VXGroups{}, RangerError{ Err: err }
    }

    defer func( Body io.ReadCloser ) {
        err := Body.Close()
        if err != nil {
            logger.Warn("Problem closing result reader: ", err)
        }
    } ( resp.Body );

    // Only accepted status is 200, even if user already existed
    if resp.StatusCode != http.StatusOK {
        logger.Debug("Unexpected status code: ", resp.Status)
        return VXGroups{}, RangerError{ resp.Status, resp.StatusCode, errors.New("Expected " + strconv.Itoa(http.StatusOK)) }
    }

    //
    // Read/verify the returned body
    //
    info := VXGroups{}

    if body, err := ioutil.ReadAll( resp.Body ); err != nil {
        logger.Warn("Problem reading the result: ", err)
    } else if err = json.Unmarshal( body, &info ); err != nil {
        logger.Warn("Problem unmarshaling the result: ", err)
        logger.Debug("Result: ", string(body))
    } else {
        logger.Debug("Result: ", string(body))
    }

    if len(info.VXGroups) == 0 {
        logger.Warn("Fetched 0 Ranger groups")
    } else {
        count := 0

        for _, group := range info.VXGroups {
            if group.IsVisible != 0 && group.GroupSource == 1 {
                count++
            }
        }

        logger.Info("Fetched ", count, " Ranger groups")
    }

    return info, RangerError{}
}

func DeleteGroup( client *http.Client, id int, name string ) RangerError {
    logger.Info("Deleting Ranger group ", name)

    url := config.Ranger.Host + config.Ranger.GroupDeleteUri + strconv.Itoa( id ) + "?forceDelete=true"

    logger.Debug("Request URL: ", url)

    // Create the GET request for the Ranger Groups API
    req, err := http.NewRequest(http.MethodDelete, url, nil)

    if err != nil {
        logger.Debug("Problem creating the request: ", err)
        return RangerError{ Err: err }
    }

    // Add any user-supplied headers
    for key, value := range config.Ranger.Headers {
        req.Header.Set( key, value )
    }

    logger.Debug("Request: ", req)

    // Check if authorization creds have been configured
    if len(config.Ranger.User) != 0 && len(config.Ranger.Pass) != 0 {
        // Need to add authorization
        req.SetBasicAuth(config.Ranger.User, config.Ranger.Pass)
    }

    // Execute the request
    resp, err := client.Do(req)

    if err != nil {
        logger.Debug("Request returned an error: ", err)
        return RangerError{ Err: err }
    }

    // Only accepted status is 204
    if resp.StatusCode != http.StatusNoContent {
        logger.Debug("Unexpected status code: ", resp.Status)
        return RangerError{ resp.Status, resp.StatusCode, errors.New("Expected " + strconv.Itoa(http.StatusNoContent)) }
    }

    logger.Info("Deleted Ranger group ", name)

    return RangerError{}
}

func GetGroupUsers( client *http.Client, name string ) (VXGroupUserInfo,RangerError) {

    logger.Info("Fetching Ranger group users for group: ", name)

    url := config.Ranger.Host + config.Ranger.GroupUsersUri + name

    logger.Debug("Request URL: ", url)

    // Create the GET request for the Ranger GroupUsers API
    req, err := http.NewRequest(http.MethodGet, url, nil)

    if err != nil {
        logger.Debug("Problem creating the request: ", err)
        return VXGroupUserInfo{}, RangerError{ Err: err }
    }

    // Add any user-supplied headers
    for key, value := range config.Ranger.Headers {
        req.Header.Set( key, value )
    }

    // Work with JSON, Ranger API defaults to XML
    req.Header.Set("Accept", "application/json")

    logger.Debug("Request: ", req)

    // Check if authorization creds have been configured
    if len(config.Ranger.User) != 0 && len(config.Ranger.Pass) != 0 {
        // Need to add authorization
        req.SetBasicAuth(config.Ranger.User, config.Ranger.Pass)
    }

    // Execute the request
    resp, err := client.Do(req)

    if err != nil {
        logger.Debug("Request returned an error: ", err)
        return VXGroupUserInfo{}, RangerError{ Err: err }
    }

    defer func( Body io.ReadCloser ) {
        err := Body.Close()
        if err != nil {
            logger.Warn("Problem closing result reader: ", err)
        }
    } ( resp.Body );

    // Only accepted status is 200, even if user already existed
    if resp.StatusCode != http.StatusOK {
        logger.Debug("Unexpected status code: ", resp.Status)
        return VXGroupUserInfo{}, RangerError{ resp.Status, resp.StatusCode, errors.New("Expected " + strconv.Itoa(http.StatusOK)) }
    }

    //
    // Read/verify the returned body
    //
    info := VXGroupUserInfo{}

    if body, err := ioutil.ReadAll( resp.Body ); err != nil {
        logger.Warn("Problem reading the result: ", err)
    } else if err = json.Unmarshal( body, &info ); err != nil {
        logger.Warn("Problem unmarshaling the result: ", err)
        logger.Debug("Result: ", string(body))
    } else {
        logger.Debug("Result: ", string(body))
    }

    if len(info.XuserInfo) == 0 {
        logger.Warn("Fetched 0 Ranger group users for: ", name)
    } else {
        logger.Info("Fetched ", len(info.XuserInfo), " Ranger group users for: ", name)
    }

    return info, RangerError{}
}

func DeleteGroupUser( client *http.Client, group string, user string ) RangerError {

    logger.Info("Deleting Ranger group user for group; ", group, " name: ", user)

    url := config.Ranger.Host + config.Ranger.GroupUserUri + group + "/user/" + user

    logger.Debug("Request URL: ", url)

    // Create the DELETE request for the Ranger GroupUser API
    req, err := http.NewRequest(http.MethodDelete, url, nil)

    if err != nil {
        logger.Debug("Problem creating the request: ", err)
        return RangerError{ Err: err }
    }

    // Add any user-supplied headers
    for key, value := range config.Ranger.Headers {
        req.Header.Set( key, value )
    }

    // Work with JSON, Ranger API defaults to XML
    req.Header.Set("Accept", "application/json")

    logger.Debug("Request: ", req)

    // Check if authorization creds have been configured
    if len(config.Ranger.User) != 0 && len(config.Ranger.Pass) != 0 {
        // Need to add authorization
        req.SetBasicAuth(config.Ranger.User, config.Ranger.Pass)
    }

    // Execute the request
    resp, err := client.Do(req)

    if err != nil {
        logger.Debug("Request returned an error: ", err)
        return RangerError{ Err: err }
    }

    defer func( Body io.ReadCloser ) {
        err := Body.Close()
        if err != nil {
            logger.Warn("Problem closing result reader: ", err)
        }
    } ( resp.Body );

    // Only accepted status is 204
    if resp.StatusCode != http.StatusNoContent {
        logger.Debug("Unexpected status code: ", resp.Status)
        return RangerError{ resp.Status, resp.StatusCode, errors.New("Expected " + strconv.Itoa(http.StatusNoContent)) }
    }

    logger.Info("Deleted Ranger group user for group; ", group, " name: ", user)

    return RangerError{}
}

func CreateGroupInfo( client *http.Client, guinfo VXGroupUserInfo ) RangerError {

    logger.Info("Creating Ranger group info for group: ", guinfo.XgroupInfo.Name)

    // Marshal the JSON for the user info
    info, err := json.Marshal( guinfo )

    if err != nil {
        logger.Debug("Problem marshaling the object: ", err)
        return RangerError{ Err: err }
    }

    url := config.Ranger.Host + config.Ranger.GroupInfoUri

    logger.Debug("Request URL: ", url)
    logger.Debug("Request Body: ", string(info))

    // Create the POST request for the Ranger create API
    req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(info))

    if err != nil {
        logger.Debug("Problem creating the request: ", err)
        return RangerError{ Err: err }
    }

    // Add any user-supplied headers
    for key, value := range config.Ranger.Headers {
        req.Header.Set( key, value )
    }

    // Work with JSON, Ranger API defaults to XML
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Accept", "application/json")

    logger.Debug("Request: ", req)

    // Check if authorization creds have been configured
    if len(config.Ranger.User) != 0 && len(config.Ranger.Pass) != 0 {
        // Need to add authorization
        req.SetBasicAuth(config.Ranger.User, config.Ranger.Pass)
    }

    // Execute the request
    resp, err := client.Do(req)

    if err != nil {
        logger.Debug("Request returned an error: ", err)
        return RangerError{ Err: err }
    }

    defer func( Body io.ReadCloser ) {
        err := Body.Close()
        if err != nil {
            logger.Warn("Problem closing result reader: ", err)
        }
    } ( resp.Body );

    // Only accepted status is 200, even if user already existed
    if resp.StatusCode != http.StatusOK {
        logger.Debug("Unexpected status code: ", resp.Status)
        return RangerError{ resp.Status, resp.StatusCode, errors.New("Expected " + strconv.Itoa(http.StatusOK)) }
    }

    //
    // Read/verify the returned body, even though we dont need it
    //
    if body, err := ioutil.ReadAll( resp.Body ); err != nil {
        logger.Warn("Problem reading the result: ", err)
    } else if err = json.Unmarshal( body, &guinfo ); err != nil {
        logger.Warn("Problem unmarshaling the result: ", err)
        logger.Debug("Result: ", string(body))
    } else {
        logger.Debug("Result: ", string(body))
    }

    logger.Info("Created Ranger group info for: ", guinfo.XgroupInfo.Name)

    return RangerError{}
}


package adsync

import (
    "crypto/tls"
    "crypto/x509"
    "errors"
    "io/ioutil"
    "net/http"
    "os"
    "sync"
    "time"
)

type empty struct{}
type semaphore chan empty

func (s semaphore) P(n int) {
    e := empty{}
    for i := 0; i < n; i++ {
        s <- e
    }
}

func (s semaphore) V(n int) {
    for i := 0; i < n; i++ {
        <-s
    }
}

func HttpClient() *http.Client {

    localCertFile := config.Tls.AdditionalCertificatesPemFilename

    if (len(localCertFile) == 0 && !config.Tls.InsecureSkipVerify) {
        logger.Debug("Skipping HTTP client TLS customization. Using system defaults")
        return &http.Client{}
    }

    rootCAs, err := x509.SystemCertPool()
    if rootCAs == nil {
        logger.Error("x509.SystemCertPool not found, creating an empty CertPool instead: ", err)
        rootCAs = x509.NewCertPool()
    }

    if len(localCertFile) > 0 {
        // Read in the cert file
        certs, err := ioutil.ReadFile(localCertFile)
        if err != nil {
            // Deliberately failing in case if file with certificates can't be read
            logger.Fatal("Failed to append cert file to RootCAs: ", localCertFile, " error: ", err)
        }
        // Append our cert to the system pool
        if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
            // Deliberately failing in case if certificates were not appended
            logger.Fatal("No certs appended, PEM file did not contain any certificates: ", localCertFile)
        } else {
            logger.Warn("Appended certs to RootCAs from ", localCertFile)
        }
    }

    if config.Tls.InsecureSkipVerify {
        logger.Warn("TLS InsecureSkipVerify enabled. Trusting all TLS certificates")
    }

    tlsconfig := &tls.Config{
        InsecureSkipVerify: config.Tls.InsecureSkipVerify,
        RootCAs:            rootCAs,
    }
    tr := &http.Transport{TLSClientConfig: tlsconfig}

    return &http.Client{Transport: tr}
}

type Adsync struct {
    client *http.Client

    // The Azure object
    azure Azure

    // Used to track existing Ranger groups
    rangerGroups map[string]int

    // Used to cache the groups that have already been created
    createdGroups map[string]int

    // List of all users that are members of created groups
    groupUsers map[string]int
}

func (a *Adsync) getRangerGroups() AdsyncError {
    // Clear any existing groups/init the map
    a.rangerGroups = make(map[string]int)

    //
    // Get the groups currently in Ranger, to see which ones might have been deleted from Azure
    //
    if gs, err := GetGroups( a.client ); ! err.Ok() {
        return AdsyncError{ Err: errors.New( "Cannot fetch groups from Ranger: " + err.Error() ) }
    } else {
        for _, group := range gs.VXGroups {
            // Only track external groups...which is GroupSource = 1
            if group.GroupSource == 1 {
                // Need the name -> id mapping for possible deletion later
                a.rangerGroups[group.Name] = group.Id
            }
        }
    }

    return AdsyncError{}
}

func (a *Adsync) getAzureGroup( id string ) (AzureGroup,AdsyncError) {
    //
    // Retries are required. If 401 is returned for a reason other than invalid token, then this would infinite loop without retries
    //
    for retries := 0; ; retries++ {
        if retries > config.Azure.AuthRetries {
            return AzureGroup{},AdsyncError{ Err: errors.New( "Exceeded maximum number of authorization retries" ) }
        }

        //
        // Fetch all the top level groups in Azure
        //
        if group, err := a.azure.GetGroup( id ); !err.Ok() {
            if err.Unauthorized() {
                // Authorization probably expired
                if err := a.azure.GetAuthorization(); !err.Ok() {
                    logger.Error("Problem getting authorization: ", err)
                    // Retry the auth request
                }
            } else {
                return AzureGroup{},AdsyncError{ Err: errors.New( "Cannot fetch groups from Azure: " + err.Error() ) }
            }
        } else {
            return group,AdsyncError{}
        }
    }
}

func (a *Adsync) getAzureGroups() AdsyncError {
    // Clear any existing group info
    a.azure.Groups = nil

    //
    // Retries are required. If 401 is returned for a reason other than invalid token, then this would infinite loop without retries
    //
    for retries := 0; ; retries++ {
        if retries > config.Azure.AuthRetries {
            return AdsyncError{ Err: errors.New( "Exceeded maximum number of authorization retries" ) }
        }

        //
        // Fetch all the top level groups in Azure
        //
        if err := a.azure.GetAllGroups(); !err.Ok() {
            if err.Unauthorized() {
                // Authorization probably expired
                if err := a.azure.GetAuthorization(); !err.Ok() {
                    logger.Error("Problem getting authorization: ", err)
                    // Retry the auth request
                }
            } else {
                return AdsyncError{ Err: errors.New( "Cannot fetch groups from Azure: " + err.Error() ) }
            }
        } else {
            break
        }
    }

    return AdsyncError{}
}

func (a *Adsync) getAzureGroupMembers( id, name string ) AdsyncError {
    //
    // Retries are required. If 401 is returned for any reason other than invalid token, causes an infinite loop without retries
    //
    for retries := 0; ; retries++ {
        if retries > config.Azure.AuthRetries {
            return AdsyncError{ Err: errors.New( "Exceeded maximum number of authorization retries" ) }
        }

        if err := a.azure.GetAllGroupMembers(id); !err.Ok() {
            if err.Unauthorized() {
                // Authorization probably expired
                if err := a.azure.GetAuthorization(); !err.Ok() {
                    logger.Error("Problem getting authorization: ", err)
                }
            } else {
                return AdsyncError{ Err: errors.New( "Cannot fetch group members from Azure: " + err.Error() ) }
            }
        } else {
            break
        }
    }

    return AdsyncError{}
}

func (a *Adsync) preProcessAzureGroup( group AzureGroup ) AdsyncError {
    //
    // Id and DisplayName are required
    //
    if group.Id == "" {
        return AdsyncError{Err: errors.New("Azure group doesn't have an Id")}
    }
    if group.DisplayName == "" {
        return AdsyncError{Err: errors.New("Azure group doesn't have a display name: : " + group.Id)}
    }

    //
    // Fetch the group members for this group
    //
    if err := a.getAzureGroupMembers(group.Id, group.DisplayName); !err.Ok() {
        return AdsyncError{Err: errors.New("Cannot fetch groups members from Azure: " + err.Error())}
    }

    return AdsyncError{}
}

func (a *Adsync) processAzureGroup( group AzureGroup, members []AzureGroupMembers ) AdsyncError {
    //
    // Check if the group had already been created
    //
    if a.createdGroups[group.Id] != 0 {
        logger.Warn("Azure group ", group.DisplayName, " had already been created. Skipping")
        return AdsyncError{}
    }

    // Track users seen in this group
    check := make(map[string]int)

    //
    // Set the group fields from the Azure info
    //
    guinfo := VXGroupUserInfo{}

    guinfo.XgroupInfo.Name = group.DisplayName
    guinfo.XgroupInfo.Description = "Imported from Active Directory"
    guinfo.XgroupInfo.GroupType = 1
    guinfo.XgroupInfo.GroupSource = 1
    guinfo.XgroupInfo.IsVisible = 1

    //
    // Create the users from the Azure info
    //
    for _, uslice := range members {
        for _, user := range uslice.Value {

            if user.OdataType != "#microsoft.graph.user" {
                logger.Info("Unsupported Azure AD Group member type: ", user.OdataType, " for: ", user.DisplayName)
                continue
            }

            if user.UserPrincipalName == "" {
                logger.Error("Azure AD User doesn't have a name: ", user.Id)
                continue
            }

            // Mark user as part of this group
            if _, ok := check[user.UserPrincipalName]; ok {
                logger.Debug( "Duplicate user ", user.UserPrincipalName, " found as member of group ", group.DisplayName )
            } else {
                check[user.UserPrincipalName] = 1
            }

            guinfo.XuserInfo = append(guinfo.XuserInfo, struct {
                CreateDate    time.Time `json:"createDate"`
                UpdateDate    time.Time `json:"updateDate"`
                Name          string    `json:"name"`
                Status        int       `json:"status"`
                IsVisible     int       `json:"isVisible"`
                UserSource    int       `json:"userSource"`
                GroupNameList []string  `json:"groupNameList"`
                UserRoleList  []string  `json:"userRoleList"`
            }{Name: user.UserPrincipalName, IsVisible: 1, UserSource: 0, GroupNameList: []string{}, UserRoleList: []string{}})

            // Mark user as part of this group
            check[user.UserPrincipalName] = 1

            // Mark user as part of any group (to be added later)
            a.groupUsers[user.UserPrincipalName] += 1
        }
    }

    if len(guinfo.XuserInfo) == 0 {
        logger.Info("Azure group ", group.DisplayName, " does not contain any users")
        return AdsyncError{}
    }

    // Remove the group from the Ranger map of groups to delete, it exists in Azure
    delete(a.rangerGroups, group.DisplayName)

    //
    // Send the group info
    //
    if a.createdGroups[group.Id] == 0 {
        if err := CreateGroupInfo(a.client, guinfo); !err.Ok() {
            return AdsyncError{ Err: errors.New( "Problem creating group info: " + err.Error() ) }
        }

        // Increment the count for that specific group
        a.createdGroups[group.Id] += 1
    } else {
        logger.Warn( "Ranger group ", group.DisplayName, " already exists" )
    }

    // Request the group info from Ranger
    info, err := GetGroupUsers(a.client, group.DisplayName)

    if !err.Ok() {
        return AdsyncError{ Err: errors.New( "Problem getting group users: " + err.Error() ) }
    }

    //
    // Need to determine if any existing users have been removed from the group
    //
    if len(info.XuserInfo) != 0 {
        // Loop over all the returned users
        for _, user := range info.XuserInfo {
            // Check if the user from the returned list is not in the group
            if _, ok := check[user.Name]; !ok {
                // Need to explicitly delete the user
                if err := DeleteGroupUser(a.client, group.DisplayName, user.Name); !err.Ok() {
                    logger.Error("Problem deleting group user: ", err)
                }
            }
        }
    }

    return AdsyncError{}
}

func (a *Adsync) groupUserSync() {
    // Create an Azure object
    a.azure = Azure{ client: a.client }

    // Request an auth token before we do anything
    err := a.azure.GetAuthorization()

    if ! err.Ok() {
        logger.Fatal("Problem getting authorization token: ", err)
    }

    // Get the groups currently in Ranger, to see which ones might have been deleted from Azure
    if err := a.getRangerGroups(); ! err.Ok() {
        logger.Error( err )
        return
    }

    // Get the top level groups currently in Azure
    if err := a.getAzureGroups(); ! err.Ok() {
        logger.Error( err )
        return
    }

    //
    // Preprocess each top level group to gather users and any nested groups
    //
    for _, group := range a.azure.Groups {
        if err := a.preProcessAzureGroup( group.AzGroup ); ! err.Ok() {
            logger.Error( err )
            return
        }
    }

    //
    // Process the nested group information
    //
    for _, top := range a.azure.Groups {
        for _, nslice := range top.AzNested {
            for _, nested := range nslice.Value {
                if group, err := a.getAzureGroup( nested.Id ); ! err.Ok() {
                    logger.Error( err )
                    return
                } else {
                    //
                    // TODO Need to do manual filtering of the nested group name?
                    //

                    //
                    // Do some additional stuff if the group doesn't already exist
                    //
                    if _, ok := a.azure.Groups[group.Id]; ! ok {
                        logger.Debug( "Nested group ", group.DisplayName, " added to list of groups to process" )

                        // Add the group to the map of groups
                        a.azure.Groups[group.Id] = Group{ AzGroup: group }

                        //
                        // Get the users associated with this group
                        //
                        if err := a.preProcessAzureGroup( group ); ! err.Ok() {
                            logger.Error( err )
                            return
                        }
                    }

                    //
                    // Add the users from the nested group to the parent/top group
                    //
                    for _, member := range a.azure.Groups[group.Id].AzMembers {
                        top.AzMembers = append( top.AzMembers, member )
                    }

                    a.azure.Groups[top.AzGroup.Id] = top
                }
            }
        }
    }

    //
    // Process each group
    //
    for _, group := range a.azure.Groups {
        if err := a.processAzureGroup( group.AzGroup, group.AzMembers ); ! err.Ok() {
            logger.Error( err )
            return
        }
    }

    f, err2 := os.Create("/tmp/groups/test.txt")
    if err2 != nil {
        panic(err2)
    }
    defer f.Close()
    logger.Info("Starting local file")
    for _, group := range a.azure.Groups {
        f.WriteString(group.AzGroup.Id)
        f.WriteString("\n")
        f.Sync()
        logger.Info(group.AzGroup.Id)
    }

    time.Sleep(300 * time.Second)



    //
    // Remove any groups in Ranger that weren't in Azure
    //
    for name, id := range a.rangerGroups {
        logger.Debug("Removing group ", name, " from Ranger")

        if err := DeleteGroup( a.client, id, name ); ! err.Ok() {
            logger.Error("Problem deleting group: ", err)
        }
    }

    //
    // Need to add users based on the users seen in the groups
    //

    // Need a wait group to allow the final threads to complete
    var wg sync.WaitGroup

    // Need to limit the number of running threads
    sem := make(semaphore, config.General.Threads)

    for name, count := range a.groupUsers {
        if count <= 0  {
            continue
        }

        // Adding one to the wait group
        wg.Add(1)

        // Increase the semaphore count
        sem.P( 1 )

        go func( x string ) {
            // Decrement the wait group count when it exits
            defer wg.Done()

            // Decrement the semaphore count when it exits
            defer sem.V( 1 )

            //
            // Populate a portal user from the group records (user exists in at least one group)
            //

            puser:= VXPortalUser{ LoginId: x }

            // Create a portal user in Ranger
            if err := CreatePortalUser( a.client, puser ); ! err.Ok() {
                logger.Error("Problem creating a portal user: ", err)
            }

            // Populate UserGroupInfo
            uginfo := VXUserGroupInfo {
                XuserInfo : struct {
                    Name          string   `json:"name"`
                    Description   string   `json:"description"`
                    GroupNameList []string `json:"groupNameList"`
                    UserRoleList  []string `json:"userRoleList"`
                } {
                    Name: x, Description: "Imported from Active Directory", GroupNameList: []string{}, UserRoleList: []string{},
                },
                XgroupInfo : []struct {
                    Name          string   `json:"name"`
                    Description   string   `json:"description"`
                } {},
            }

            // Create userinfo in Ranger
            if err := CreateUserInfo( a.client, uginfo ); ! err.Ok() {
                logger.Error("Problem creating user info: ", err)
            }
        }(name)
    }

    // Wait for the rest of the threads to finish
    wg.Wait()
}

func GroupUserSync() {
    // Create a shared client object
    client := HttpClient()

    // Create an Adsync object
    async := Adsync{ client: client, createdGroups: make(map[string]int,5), groupUsers: make(map[string]int,5) }

    // Run the sync
    async.groupUserSync()
}

package adsync

import (
    "crypto/tls"
    "crypto/x509"
    "io/ioutil"
    "net/http"
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

func GroupUserSync() {

    // Create a shared client object
    client := HttpClient()

    // Create an Azure object
    azure := Azure{ client: client }

    // Request an auth token
    err := azure.GetAuthorization()

    if ! err.Ok() {
        logger.Fatal("Problem getting token: ", err)
    }

    //
    // Get the groups currently in Ranger, to see which ones might have been deleted from Azure
    //

    groups := make(map[string]int)

    if gs, err := GetGroups( client ); ! err.Ok() {
        logger.Error("Cannot fetch groups from Ranger: ", err)
    } else {
        for _, group := range gs.VXGroups {
            // Only track external groups...which is GroupSource = 1
            if group.GroupSource == 1 {
                // Need the name -> id mapping for possible deletion later
                groups[group.Name] = group.Id
            }
        }
    }

    //
    // Retries are required. If 401 is returned for a reason other than invalid token, then this would infinite loop without retries
    //
    for retries := 0; ; retries++ {
        if retries > config.Azure.AuthRetries {
            logger.Error("Exceeded maximum number of authorization retries")
            return
        }

        //
        // Fetch all the groups in Azure
        //
        if err := azure.GetAllGroups(); !err.Ok() {
            if err.Unauthorized() {
                // Authorization probably expired
                if err := azure.GetAuthorization(); !err.Ok() {
                    logger.Error("Problem getting authorization: ", err)
                }
            } else {
                logger.Error("Problem getting groups: ", err)
                return
            }
        } else {
            break
        }
    }

    // Track list of users associated with Azure groups
    users := make(map[string]int)

    //
    // Process the groups from Azure
    //
    for _, group := range azure.Groups.Value {
        if group.DisplayName == "" {
            logger.Error("Azure AD Group doesn't have a name: ", group.Id)
            continue
        }

        // Track users seen in this group
        check := make(map[string]int)

        //
        // Retries are required. If 401 is returned for any reason other than invalid token, causes an infinite loop without retries
        //
        for retries := 0; ; retries++ {
            if retries > config.Azure.AuthRetries {
                logger.Error("Exceeded maximum number of authorization retries")
                return
            }

            if err := azure.GetAllGroupMembers(group.Id, group.DisplayName); !err.Ok() {
                if err.Unauthorized() {
                    // Authorization probably expired
                    if err := azure.GetAuthorization(); !err.Ok() {
                        logger.Error("Problem getting authorization: ", err)
                    }
                } else {
                    logger.Error("Problem getting group members: ", err)
                    return
                }
            } else {
                break
            }
        }

        guinfo := VXGroupUserInfo{}

        //
        // Set the group fields from the Azure info
        //
        guinfo.XgroupInfo.Name = group.DisplayName
        guinfo.XgroupInfo.Description = "Imported from Active Directory"
        guinfo.XgroupInfo.GroupType = 1
        guinfo.XgroupInfo.GroupSource = 1
        guinfo.XgroupInfo.IsVisible = 1

        //
        // Create the users from the Azure info
        //
        for _, user := range azure.Members.Value {

            if user.OdataType != "#microsoft.graph.user" {
                logger.Warn("Unsupported Azure AD Group member type: ", user.OdataType, " for id: ", user.Id)
                continue
            }

            if user.UserPrincipalName == "" {
                logger.Error("Azure AD User doesn't have a name: ", user.Id)
                continue
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
            users[user.UserPrincipalName] += 1
        }

        if len(guinfo.XuserInfo) == 0 {
            logger.Warn("Group does not contain any member of type user. Treating it as if it doesn't exist in Azure: ", group.DisplayName)
            continue
        }

        // Remove the group from the Ranger map of groups to delete, it exists in Azure
        delete(groups, group.DisplayName)

        //
        // Send the group info
        //
        if err := CreateGroupInfo(client, guinfo); !err.Ok() {
            logger.Error("Problem creating group info: ", err)
            continue
        }

        // Request the group info from Ranger
        info, err := GetGroupUsers(client, group.DisplayName)

        if !err.Ok() {
            logger.Error("Problem getting group users: ", err)
            return
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
                    if err := DeleteGroupUser(client, group.DisplayName, user.Name); !err.Ok() {
                        logger.Error("Problem deleting group user: ", err)
                    }
                }
            }
        }
    }

    //
    // Remove any groups in Ranger that weren't in Azure
    //

    for name, id := range groups {
        logger.Debug("Removing group ", name, " from Ranger")

        if err := DeleteGroup( client, id ); ! err.Ok() {
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

    for name, count := range users {
        if( count <= 0 ) {
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
            if err := CreatePortalUser( client, puser ); ! err.Ok() {
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
            if err := CreateUserInfo( client, uginfo ); ! err.Ok() {
                logger.Error("Problem creating user info: ", err)
            }
        }(name)
    }

    // Wait for the rest of the threads to finish
    wg.Wait()
}

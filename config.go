package adsync

import (
	"os"
	"strconv"
	"strings"
)

type AzureConfig struct {
	TenantId     string
	ClientId     string
	ClientSecret string

	AuthRetries           int
	GroupFilter           []string
	SyncServicePrincipals bool
}

type RangerConfig struct {
	Host string
	User string
	Pass string

	CreateUserUri  string
	UpdateUserUri  string
	DeleteUserUri  string
	UserInfoUri    string
	GroupsUri      string
	GroupUsersUri  string
	GroupInfoUri   string
	GroupUserUri   string
	GroupDeleteUri string

	GroupInfoLimit int

	Headers map[string]string
}

type GeneralConfig struct {
	Threads int
}

type TlsConfig struct {
	InsecureSkipVerify                bool
	AdditionalCertificatesPemFilename string
}

type GroupFileConfig struct {
	CreateGroupFile bool
	GroupFilePath   string
	GroupFileName   string
}

type Config struct {
	Azure     AzureConfig
	Ranger    RangerConfig
	General   GeneralConfig
	Tls       TlsConfig
	GroupFile GroupFileConfig
}

func NewConfig() Config {

	ok := true

	//
	// Required Azure
	//

	tenantId, present := os.LookupEnv("AZURE_TENANT_ID")
	if !present {
		logger.Error("AZURE_TENANT_ID is not set")
		ok = false
	}

	clientId, present := os.LookupEnv("AZURE_CLIENT_ID")
	if !present {
		logger.Error("AZURE_CLIENT_ID is not set")
		ok = false
	}

	clientSecret, present := os.LookupEnv("AZURE_CLIENT_SECRET")
	if !present {
		logger.Error("AZURE_CLIENT_SECRET is not set")
		ok = false
	}

	//
	// Optional Azure
	//

	authRetries := 1

	retries, present := os.LookupEnv("AZURE_AUTH_RETRIES")
	if present {
		if i, e := strconv.Atoi(retries); e != nil {
			logger.Error("AZURE_AUTH_RETRIES is not a valid number")
			ok = false
		} else {
			authRetries = i
		}
	}

	groupFilter := []string{}

	if filter, present := os.LookupEnv("AZURE_GROUP_FILTER"); present {
		if len(filter) > 0 {
			// Semicolon separated list
			groupFilter = strings.Split(filter, ";")
		}
	}

	syncServicePrincipals := false
	sp, present := os.LookupEnv("AZURE_SYNC_SERVICE_PRINCIPALS")
	if present {
		if i, e := strconv.ParseBool(sp); e != nil {
			logger.Error("AZURE_SYNC_SERVICE_PRINCIPALS is not a valid bool")
			ok = false
		} else {
			syncServicePrincipals = i
		}
	}

	//
	// Required Ranger
	//

	rangerHost, present := os.LookupEnv("RANGER_HOST")
	if !present {
		logger.Error("RANGER_HOST is not set")
		ok = false
	}

	rangerUser, present := os.LookupEnv("RANGER_USER")
	if !present {
		logger.Error("RANGER_USER is not set")
		ok = false
	}

	rangerPass, present := os.LookupEnv("RANGER_PASS")
	if !present {
		logger.Error("RANGER_PASS is not set")
		ok = false
	}

	//
	// Optional Ranger
	//

	createUserUri, present := os.LookupEnv("RANGER_CREATE_USER_URI")
	if !present {
		createUserUri = "/service/users/default"
	}

	updateUserUri, present := os.LookupEnv("RANGER_UPDATE_USER_URI")
	if !present {
		updateUserUri = "/service/users"
	}

	deleteUserUri, present := os.LookupEnv("RANGER_UPDATE_USER_URI")
	if !present {
		deleteUserUri = "/service/xusers/users/"
	} else if !strings.HasSuffix(deleteUserUri, "/") {
		deleteUserUri += "/"
	}

	userInfoUri, present := os.LookupEnv("RANGER_USER_INFO_URI")
	if !present {
		userInfoUri = "/service/xusers/users/userinfo"
	}

	groupsUri, present := os.LookupEnv("RANGER_GROUPS_URI")
	if !present {
		groupsUri = "/service/xusers/groups/"
	} else if !strings.HasSuffix(groupsUri, "/") {
		groupsUri += "/"
	}

	groupUsersUri, present := os.LookupEnv("RANGER_GROUP_USERS_URI")
	if !present {
		groupUsersUri = "/service/xusers/groupusers/groupName/"
	} else if !strings.HasSuffix(groupUsersUri, "/") {
		groupUsersUri += "/"
	}

	groupInfoUri, present := os.LookupEnv("RANGER_GROUP_INFO_URI")
	if !present {
		groupInfoUri = "/service/xusers/groups/groupinfo"
	}

	groupUserUri, present := os.LookupEnv("RANGER_GROUP_USER_URI")
	if !present {
		groupUserUri = "/service/xusers/group/"
	} else if !strings.HasSuffix(groupUserUri, "/") {
		groupUserUri += "/"
	}

	groupDeleteUri, present := os.LookupEnv("RANGER_GROUP_DELETE_URI")
	if !present {
		groupDeleteUri = "/service/xusers/secure/groups/id/"
	} else if !strings.HasSuffix(groupsUri, "/") {
		groupDeleteUri += "/"
	}

	groupInfoLimit := 0

	limit, present := os.LookupEnv("RANGER_GROUP_INFO_LIMIT")
	if present {
		if i, e := strconv.Atoi(limit); e != nil {
			logger.Error("RANGER_GROUP_INFO_LIMIT is not a valid number")
			ok = false
		} else {
			groupInfoLimit = i
		}
	}

	//
	// General config
	//

	threads := 1

	t, present := os.LookupEnv("ADSYNC_THREADS")
	if present {
		if i, e := strconv.Atoi(t); e != nil {
			logger.Error("ADSYNC_THREADS is not a valid number")
			ok = false
		} else {
			threads = i
		}
	}

	if level, present := os.LookupEnv("ADSYNC_LOG_LEVEL"); present {
		switch strings.ToUpper(level) {
		case "DEBUG":
			logger.Level = DEBUG
		case "INFO":
			logger.Level = INFO
		case "WARN":
			logger.Level = WARN
		case "ERROR":
			logger.Level = ERROR
		case "FATAL":
			logger.Level = FATAL
		default:
			logger.Level = INFO
		}
	}

	// TLS Config
	insecureSkipVerify := false
	s, present := os.LookupEnv("TLS_INSECURE_SKIP_VERIFY")
	if present {
		if i, e := strconv.ParseBool(s); e != nil {
			logger.Error("TLS_INSECURE_SKIP_VERIFY is not a valid bool")
			ok = false
		} else {
			insecureSkipVerify = i
		}
	}

	var certFilename string
	c, present := os.LookupEnv("TLS_ADDITIONAL_CERTIFICATES_PEM_FILENAME")
	if present {
		certFilename = c
	}

	//File Group Provider Config
	createGroupFile := false
	cg, present := os.LookupEnv("CREATE_GROUP_FILE")
	if present {
		if i, e := strconv.ParseBool(cg); e != nil {
			logger.Error("CREATE_GROUP_FILE is not a valid bool")
			ok = false
		} else {
			createGroupFile = i
		}
	}

	var groupFilePath string
	gf, present := os.LookupEnv("GROUP_FILE_PATH")
	if present {
		groupFilePath = gf
	}

	var groupFileName string
	gn, present := os.LookupEnv("GROUP_FILE_NAME")
	if present {
		groupFileName = gn
	}

	//
	// Sanity check
	//

	if !ok {
		logger.Fatal("Required configuration parameters were not found")
	}

	return Config{
		Azure: AzureConfig{
			TenantId:              tenantId,
			ClientId:              clientId,
			ClientSecret:          clientSecret,
			AuthRetries:           authRetries,
			GroupFilter:           groupFilter,
			SyncServicePrincipals: syncServicePrincipals,
		},
		Ranger: RangerConfig{
			Host:           rangerHost,
			User:           rangerUser,
			Pass:           rangerPass,
			CreateUserUri:  createUserUri,
			UpdateUserUri:  updateUserUri,
			DeleteUserUri:  deleteUserUri,
			UserInfoUri:    userInfoUri,
			GroupsUri:      groupsUri,
			GroupUsersUri:  groupUsersUri,
			GroupInfoUri:   groupInfoUri,
			GroupUserUri:   groupUserUri,
			GroupDeleteUri: groupDeleteUri,
			GroupInfoLimit: groupInfoLimit,
		},
		General: GeneralConfig{
			Threads: threads,
		},
		Tls: TlsConfig{
			InsecureSkipVerify:                insecureSkipVerify,
			AdditionalCertificatesPemFilename: certFilename,
		},
		GroupFile: GroupFileConfig{
			CreateGroupFile: createGroupFile,
			GroupFilePath:   groupFilePath,
			GroupFileName:   groupFileName,
		},
	}
}

var config = NewConfig()

func RangerHeaders(headers map[string]string) {
	//
	// Basically going to assume the caller sent in valid data
	//

	// Save the headers for use later on
	config.Ranger.Headers = headers
}

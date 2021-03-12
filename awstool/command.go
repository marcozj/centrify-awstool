package awstool

import (
	"flag"
	"fmt"
	"os"
)

// getCmdParms parse command line argument
func (c *AWSClient) getCmdParms() {
	// Common arguments
	authTypePtr := flag.String("auth", "oauth", "Authentication type <oauth|unpw|dmc>")
	urlPtr := flag.String("url", "", "Centrify tenant URL (Required)")
	regionPtr := flag.String("region", "ap-southeast-1", "AWS region")
	skipCertPtr := flag.Bool("skipcert", false, "Ignore certification verification")
	debugPtr := flag.Bool("debug", false, "Trun on debug logging")

	// Other arguments
	appIDPtr := flag.String("appid", "", "OAuth application ID. Required if auth = oauth")
	scopePtr := flag.String("scope", "", "OAuth or DMC scope definition. Required if auth = oauth or dmc")
	tokenPtr := flag.String("token", "", "OAuth or DMC token. Optional if auth = oauth or dmc")
	usernamePtr := flag.String("user", "", "Authorized user to login to tenant. Required if auth = unpw. Optional if auth = oauth")
	passwordPtr := flag.String("password", "", "User password. You will be prompted to enter password if this isn't provided")

	flag.Usage = func() {
		fmt.Printf("Usage: centrifyawcli -auth oauth -url https://tenant.my.centrify.net -user user@company.com \n")
		flag.PrintDefaults()
	}

	flag.Parse()

	// Verify command argument length
	if len(os.Args) < 2 {
		flag.Usage()
		os.Exit(1)
	}

	// Verify authTypePtr value
	authChoices := map[string]bool{"oauth": true, "unpw": true, "dmc": true}
	if _, validChoice := authChoices[*authTypePtr]; !validChoice {
		flag.Usage()
		os.Exit(1)
	}
	// Check required argument that do not have default value
	if *urlPtr == "" {
		flag.Usage()
		os.Exit(1)
	}

	switch *authTypePtr {
	case "oauth":
		if *appIDPtr == "" || *scopePtr == "" {
			flag.Usage()
			os.Exit(1)
		}
		// Either token or username must be provided
		if *tokenPtr == "" && *usernamePtr == "" {
			flag.Usage()
			os.Exit(1)
		}
	case "unpw":
		if *urlPtr == "" || *usernamePtr == "" {
			flag.Usage()
			os.Exit(1)
		}
	case "dmc":
		if *tokenPtr == "" && *scopePtr == "" {
			flag.Usage()
			os.Exit(1)
		}
	}

	// Assign argument values to struct
	c.auth = *authTypePtr
	c.url = *urlPtr
	c.appid = *appIDPtr
	c.scope = *scopePtr
	c.token = *tokenPtr
	c.user = *usernamePtr
	c.password = *passwordPtr
	c.skipcert = *skipCertPtr
	c.awsRegion = *regionPtr
	c.debug = *debugPtr
}

func (c *AWSClient) getCmdParms2() {
	regionPtr := flag.String("region", "us-west-2", "AWS region. Default is us-west-2")
	debugPtr := flag.Bool("debug", false, "Trun on debug logging")
	_, _ = regionPtr, debugPtr

	oauthCmd := flag.NewFlagSet(OAUTH, flag.ExitOnError)
	simpleCmd := flag.NewFlagSet(UNPW, flag.ExitOnError)
	dmcCmd := flag.NewFlagSet(DMC, flag.ExitOnError)

	// Oauth command flags
	oauthURL := oauthCmd.String("url", "", "Centrify tenant URL. (Required)")
	oauthAppID := oauthCmd.String("appid", "", "OAuth application ID. (Required)")
	oauthScope := oauthCmd.String("scope", "", "OAuth scope definition. (Required)")
	oauthToken := oauthCmd.String("token", "", "OAuth token.")
	oauthUsername := oauthCmd.String("user", "", "Authorized user (Oauth) to login to tenant.")
	oauthPassword := oauthCmd.String("password", "", "User password")
	oauthSkipCert := oauthCmd.Bool("skipcert", false, "Ignore certification verification")

	// User command flags
	simpleURL := simpleCmd.String("url", "", "Centrify tenant URL. (Required)")
	simpleUsername := simpleCmd.String("user", "", "Authorized user (interactive) to login to tenant. (Required)")
	//simplePassword := simpleCmd.String("password", "", "User password")
	simpleSkipCert := simpleCmd.Bool("skipcert", false, "Ignore certification verification")

	// DMC command flags
	dmcURL := dmcCmd.String("url", "", "Centrify tenant URL. (Required)")
	dmcToken := dmcCmd.String("token", "", "Delegated machine credential token.")
	dmcScope := dmcCmd.String("scope", "", "DMC scope definition.")
	dmcSkipCert := dmcCmd.Bool("skipcert", false, "Ignore certification verification")

	flag.Parse()
	// Verify that a subcommand has been provided
	// os.Arg[0] is the main command
	// os.Arg[1] will be the subcommand
	if len(os.Args) < 2 {
		fmt.Println("oauth, simple or dmc subcommand is required")
		flag.Usage()
		os.Exit(1)
	}

	// Switch on the subcommand
	// Parse the flags for appropriate FlagSet
	// FlagSet.Parse() requires a set of arguments to parse as input
	// os.Args[2:] will be all arguments starting after the subcommand at os.Args[1]
	switch os.Args[1] {
	case OAUTH:
		if err := oauthCmd.Parse(os.Args[2:]); err != nil {
			oauthCmd.PrintDefaults()
			os.Exit(1)
		}
		// Check oauth sub command
		if oauthCmd.Parsed() {
			if *oauthURL == "" || *oauthAppID == "" || *oauthScope == "" {
				oauthCmd.PrintDefaults()
				os.Exit(1)
			}
			// Either token or username must be provided
			if *oauthToken == "" && *oauthUsername == "" {
				oauthCmd.PrintDefaults()
				os.Exit(1)
			}
			c.auth = OAUTH
			c.url = *oauthURL
			c.appid = *oauthAppID
			c.scope = *oauthScope
			c.token = *oauthToken
			c.user = *oauthUsername
			c.password = *oauthPassword
			c.skipcert = *oauthSkipCert
		}
	case UNPW:
		if err := simpleCmd.Parse(os.Args[2:]); err != nil {
			simpleCmd.PrintDefaults()
			os.Exit(1)
		}
		// Check user sub command
		if simpleCmd.Parsed() {
			if *simpleURL == "" || *simpleUsername == "" {
				simpleCmd.PrintDefaults()
				os.Exit(1)
			}
			c.auth = UNPW
			c.url = *simpleURL
			c.user = *simpleUsername
			//c.password = *simplePassword
			c.skipcert = *simpleSkipCert
		}
	case DMC:
		if err := dmcCmd.Parse(os.Args[2:]); err != nil {
			oauthCmd.PrintDefaults()
			os.Exit(1)
		}
		if dmcCmd.Parsed() {
			if *dmcURL == "" || (*dmcToken == "" && *dmcScope == "") {
				dmcCmd.PrintDefaults()
				os.Exit(1)
			}
			c.auth = DMC
			c.url = *dmcURL
			c.token = *dmcToken
			c.scope = *dmcScope
			c.skipcert = *dmcSkipCert
		}
	default:
		fmt.Println("oauth, simple or dmc subcommand is required")
		os.Exit(1)
	}

}

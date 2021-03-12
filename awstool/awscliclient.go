package awstool

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	saml "github.com/edaniels/go-saml"
	"github.com/marcozj/golang-sdk/dmc"
	log "github.com/marcozj/golang-sdk/logging"
	"github.com/marcozj/golang-sdk/oauth"
	"github.com/marcozj/golang-sdk/restapi"
	"github.com/marcozj/golang-sdk/webcookie"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/net/html"
)

const (
	// OAUTH oauth authenticaiton type
	OAUTH string = "oauth"
	// UNPW username and password authentication type
	UNPW string = "unpw"
	// DMC Delegated Machine Credential authentication type
	DMC string = "dmc"
)

// AWSClient represents a clien structure
type AWSClient struct {
	Client    *restapi.RestClient
	auth      string
	url       string
	appid     string
	scope     string
	token     string
	user      string
	password  string
	skipcert  bool
	awsRegion string
	debug     bool
}

type awsRoleAttrs struct {
	role     string
	provider string
}

type samlResponse struct {
	resp        *saml.Response
	encodedsaml string
}

// NewClient initiates a client
func NewClient() *AWSClient {
	return &AWSClient{}
}

// Run executes the program
func (c *AWSClient) Run() error {
	// Get command line parameters
	c.getCmdParms()

	// Get REST client
	var err error
	c.Client, err = c.getRestClient()
	if err != nil {
		return err
	}

	// Retrieve AWS Web applications
	awsapps, err := c.getApps()
	if err != nil {
		return err
	}

	// Select an AWS web appliation if there are more than one
	appkey, err := selectApp(awsapps)
	if err != nil {
		return err
	}

	// Launch the selected AWS web application to get SAML response
	saml, err := c.launchApp(appkey)
	if err != nil {
		return err
	}

	// Select role if there are more than 1
	role, err := selectRole(saml)
	if err != nil {
		return err
	}

	// Get AWS access token
	output, err := awsAssumeRole(role, saml.encodedsaml)
	if err != nil {
		return err
	}

	// Update AWS shared credential file
	err = c.updateCredentialFile(output)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully retrieved temporary AWS access key that will expire on %v\n", output.Credentials.Expiration)
	return nil
}

// GetRestClient returns REST client
func (c *AWSClient) getRestClient() (*restapi.RestClient, error) {
	var restClient *restapi.RestClient
	var err error
	switch c.auth {
	case OAUTH:
		call := oauth.OauthClient{
			Service:        c.url,
			AppID:          c.appid,
			Scope:          c.scope,
			ClientID:       c.user,
			ClientSecret:   c.password,
			SkipCertVerify: c.skipcert,
		}
		if call.ClientSecret == "" {
			fmt.Print("Enter Password: ")
			bytePassword, _ := terminal.ReadPassword(int(syscall.Stdin))
			password := strings.TrimSpace(string(bytePassword))
			call.ClientSecret = password
			fmt.Println()
		}
		restClient, err = call.GetClient()
		if err != nil {
			return nil, fmt.Errorf("Unable to get oauth rest client: %v", err)
		}
	case UNPW:
		call := webcookie.WebCookie{}
		call.Service = c.url
		call.ClientID = c.user
		call.ClientSecret = c.password
		call.SkipCertVerify = c.skipcert

		restClient, err = call.GetClient()
		if err != nil {
			return nil, fmt.Errorf("Unable to get simple rest client: %v", err)
		}
	case DMC:
		call := dmc.DMC{}
		call.Service = c.url
		call.Scope = c.scope
		call.Token = c.token
		call.SkipCertVerify = c.skipcert

		restClient, err = call.GetClient()
		if err != nil {
			return nil, fmt.Errorf("Unable to get DMC rest client: %v", err)
		}
	}
	return restClient, nil
}

// GetApps retrieves AWS web apps that are granted Run permission for the calling user
func (c *AWSClient) getApps() ([]map[string]interface{}, error) {
	var queryArg = make(map[string]interface{})
	var args = make(map[string]interface{})
	args["Caching"] = -1
	queryArg["Args"] = args
	var method = "/uprest/getupdata"
	resp, err := c.Client.CallGenericMapAPI(method, queryArg)
	if err != nil {
		return nil, fmt.Errorf("Failed to retrieve applications from tenant: %+v", err)
	}
	//fmt.Printf("Respond: %v\n", resp.Result["Apps"])
	log.Debugf("Respond: %v\n", resp.Result["Apps"])
	apps := resp.Result["Apps"]
	//fmt.Printf("%v\n", len(apps.([]interface{})))
	var awsApps []map[string]interface{}
	for _, app := range apps.([]interface{}) {
		templateName := app.(map[string]interface{})["TemplateName"]
		webAppType := app.(map[string]interface{})["WebAppTypeDisplayName"]
		awsAccountID := app.(map[string]interface{})["CorpIdentifier"]
		if templateName != nil && webAppType != nil && awsAccountID != nil && templateName.(string) == "AWSConsoleSAML" &&
			webAppType.(string) == "SAML" && awsAccountID.(string) != "" {
			awsApps = append(awsApps, app.(map[string]interface{}))
		}
		/*
			appName := app.(map[string]interface{})["Name"]
				if appName == "Azure Portal" {
					awsApps = append(awsApps, app.(map[string]interface{}))
				}
		*/
	}
	//fmt.Printf("AWS Apps: %+v\n", awsApps)
	return awsApps, nil
}

// SelectApp prompts user to select an AWS application
// If there are multiple AWS web apps defined, prompt user to select one
func selectApp(apps []map[string]interface{}) (string, error) {
	var app map[string]interface{}
	if len(apps) > 1 {
		// Display app
		fmt.Printf("\n\n")
		for i, app := range apps {
			displayNum := i + 1
			fmt.Printf("%d. %s\n", displayNum, app["Name"])
		}
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Please select an AWS application: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSuffix(input, "\n")
		choice, err := strconv.Atoi(input)
		choice = choice - 1
		if choice < 0 || choice > len(apps)-1 || err != nil {
			return "", fmt.Errorf("Invalid choice of AWS application: %v", input)
		}
		app = apps[choice]
	} else {
		// Only one mechanism so go ahead to ask for credential
		app = apps[0]

	}
	log.Debugf("selected app: %+v\n", app)
	return app["AppKey"].(string), nil
}

func getSAMLResponse(node *html.Node) string {
	type element struct {
		name  string
		value string
	}
	var saml string

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			thisElement := &element{}
			for _, element := range n.Attr {
				//fmt.Printf("Key: %v, value: %v, namespace: %v\n", element.Key, element.Val, element.Namespace)
				switch element.Key {
				case "name":
					thisElement.name = element.Val
				case "value":
					thisElement.value = element.Val
				}
			}
			//fmt.Printf("element struct: %+v\n", thisElement)
			if thisElement.name == "SAMLResponse" {
				saml = thisElement.value
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(node)

	//fmt.Printf("SAML token: %v\n", saml)
	return saml
}

// LaunchApp runs AWS application to obtain SAML token
func (c *AWSClient) launchApp(appID string) (*samlResponse, error) {
	// Perform AWS web application run
	var queryArg = make(map[string]interface{})
	queryArg["AppKey"] = appID
	var method = "/uprest/handleAppClick"
	resp, err := c.Client.CallRawAPI(method, queryArg)
	if err != nil {
		return nil, err
	}
	//fmt.Printf("AppClick resp: %s\n", resp)
	// Get and decode SAML response
	doc, err := html.Parse(bytes.NewReader(resp))
	if err != nil {
		return nil, err
	}
	encodedSAML := getSAMLResponse(doc)
	//fmt.Printf("SAML: %v\n", encodedSAML)
	log.Debugf("Base64 encoded SAML: %+v\n", encodedSAML)
	decoded, _ := base64.StdEncoding.DecodeString(encodedSAML)
	log.Debugf("Decoded SAML: %+v\n", string(decoded))

	// Covent to struct and get AWS role information
	samlresp := &saml.Response{}
	err = xml.Unmarshal(decoded, &samlresp)
	if err != nil {
		return nil, err
	}

	//log.Debugf("SAML struct: %+v\n", samlresp.Assertion)
	return &samlResponse{resp: samlresp, encodedsaml: encodedSAML}, nil
}

// SelectRole prompts user to select a role
func selectRole(sr *samlResponse) (awsRoleAttrs, error) {
	role := awsRoleAttrs{}

	// Extract roles from SAML assertion
	rolesets := []awsRoleAttrs{}
	// Loop through <AttributeStatement>
	for _, attr := range sr.resp.Assertion.AttributeStatement.Attributes {
		if attr.Name == "https://aws.amazon.com/SAML/Attributes/Role" {
			// Loop through <AttributeValue>
			roleset := awsRoleAttrs{}
			for _, v := range attr.Values {
				str := strings.Split(v.Value, ",")
				roleset.role = str[0]
				roleset.provider = str[1]
				rolesets = append(rolesets, roleset)
			}
		}
	}

	if len(rolesets) < 1 {
		return role, fmt.Errorf("There is no role to select")
	}

	if len(rolesets) > 1 {
		// Display roles
		fmt.Printf("\n")
		for i, r := range rolesets {
			displayNum := i + 1
			fmt.Printf("%d. %s\n", displayNum, r.role)
		}
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Please select a role: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSuffix(input, "\n")
		choice, err := strconv.Atoi(input)
		choice = choice - 1
		if choice < 0 || choice > len(rolesets)-1 || err != nil {
			return role, fmt.Errorf("Invalid choice of role: %v", input)
		}
		role = rolesets[choice]
	} else if len(rolesets) == 1 {
		role = rolesets[0]
	}
	log.Debugf("selected role: %+v\n", role)
	return role, nil
}

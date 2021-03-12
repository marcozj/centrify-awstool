package awstool

import (
	"os"
	"os/user"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/bigkevmcd/go-configparser"
	log "github.com/marcozj/golang-sdk/logging"
)

func awsAssumeRole(r awsRoleAttrs, saml string) (*sts.AssumeRoleWithSAMLOutput, error) {
	mySession := session.Must(session.NewSession())
	// Create a STS client from just a session.
	svc := sts.New(mySession)

	params := &sts.AssumeRoleWithSAMLInput{
		PrincipalArn:    aws.String(r.provider), // Required
		RoleArn:         aws.String(r.role),     // Required
		SAMLAssertion:   aws.String(saml),       // Required
		DurationSeconds: aws.Int64(3600),
	}
	resp, err := svc.AssumeRoleWithSAML(params)
	if err != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		//fmt.Println(err.Error())
		return nil, err
	}
	log.Debugf("STS resp: %v\n", resp)

	return resp, nil
}

func (c *AWSClient) updateCredentialFile(op *sts.AssumeRoleWithSAMLOutput) error {
	user, err := user.Current()
	if err != nil {
		log.Fatalf(err.Error())
	}
	homedir := user.HomeDir

	credfile := homedir + "/.aws/credentials"
	//fmt.Printf("filepath: %s\n", credfile)
	// Create the file if it doesn't exist

	file, err := os.OpenFile(credfile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	file.Close()

	p, err := configparser.NewConfigParserFromFile(credfile)
	if err != nil {
		return err
	}
	str := strings.Split(*op.AssumedRoleUser.Arn, "/")
	section := str[1]

	// Remove existing section first
	if p.HasSection(section) {
		p.RemoveSection(section)
	}
	p.AddSection(section)
	p.Set(section, "aws_access_key_id", *op.Credentials.AccessKeyId)
	p.Set(section, "aws_secret_access_key", *op.Credentials.SecretAccessKey)
	p.Set(section, "aws_session_token", *op.Credentials.SessionToken)
	p.Set(section, "region", c.awsRegion)
	err = p.SaveWithDelimiter(credfile, "=")
	if err != nil {
		return err
	}
	return nil
}

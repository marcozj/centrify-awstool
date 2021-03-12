# AWS CLI Utility

This is a Go port of [Centrify AWS CLI Utility](https://github.com/centrify/centrify-aws-cli-utilities).

## Building Utility

Clone repository and build it

```sh
git clone https://github.com/marcozj/centrify-awstool
cd centrify-awstool
go build centrifyawstool.go
```

## Use Utility

Run the utility outputs help menu.

```sh
$ ./centrifyawstool 
Usage: centrifyawcli -auth oauth -url https://tenant.my.centrify.net -user user@company.com 
  -appid string
        OAuth application ID. Required if auth = oauth
  -auth string
        Authentication type <oauth|unpw|dmc> (default "oauth")
  -debug
        Trun on debug logging
  -password string
        User password. You will be prompted to enter password if this isn\'t provided
  -region string
        AWS region (default "ap-southeast-1")
  -scope string
        OAuth or DMC scope definition. Required if auth = oauth or dmc
  -skipcert
        Ignore certification verification
  -token string
        OAuth or DMC token. Optional if auth = oauth or dmc
  -url string
        Centrify tenant URL (Required)
  -user string
        Authorized user to login to tenant. Required if auth = unpw. Optional if auth = oauth
```

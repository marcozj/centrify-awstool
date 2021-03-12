package main

import (
	"fmt"
	"os"

	"github.com/marcozj/centrify-awstool/awstool"
	log "github.com/marcozj/golang-sdk/logging"
)

func main() {
	log.SetLevel(log.LevelDebug)
	log.SetLogPath("centrifyawstool.log")
	cli := awstool.NewClient()

	err := cli.Run()
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

}

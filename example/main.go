package main

import (
	"github.com/FrozenFort/anonymous_email_client_go/config"
	"log"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	client "github.com/FrozenFort/anonymous_email_client_go/example/app_client"
	server "github.com/FrozenFort/anonymous_email_client_go/example/app_service"
)

const (
	teeConfigPath    = "./testdata/tee.yaml"
	serverConfigPath = "./testdata/server.yaml"
	clientConfigPath = "./testdata/client.yaml"

	testEmail  = "zephyreusaugustus"
	testDomain = "gmail.com"
)

func main() {
	teeFile, err := os.Open(teeConfigPath)
	if err != nil {
		log.Fatalf("fail to read from configuration file [%s]: %v", teeConfigPath, err)
	}
	defer teeFile.Close()
	var teeConf config.Config
	decoderTEE := yaml.NewDecoder(teeFile)
	if err := decoderTEE.Decode(&teeConf); err != nil {
		log.Fatalf("fail to decode configuration file [%s]: %v", teeConfigPath, err)
	}

	serverFile, err := os.Open(serverConfigPath)
	if err != nil {
		log.Fatalf("fail to read from configuration file [%s]: %v", serverConfigPath, err)
	}
	defer serverFile.Close()
	var serverConf config.Config
	decoderServer := yaml.NewDecoder(serverFile)
	if err := decoderServer.Decode(&serverConf); err != nil {
		log.Fatalf("fail to decode configuration file [%s]: %v", serverConfigPath, err)
	}

	go server.StartAppService(&teeConf, &serverConf)

	time.Sleep(5 * time.Second)

	c, err := client.NewTEEClientFromConfigFile(clientConfigPath)
	if err != nil {
		panic(err)
	}
	ekPEM, err := c.Attest()
	if err != nil {
		panic(err)
	}
	err = c.SendAnonyEmail(testEmail, testDomain, ekPEM)
	if err != nil {
		panic(err)
	}
}

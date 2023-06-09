package anonymous_email_client_go

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"log"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/FrozenFort/anonymous_email_client_go/config"
	pb "github.com/FrozenFort/anonymous_email_client_go/pb/tee_anony_email"
)

type TEEClient struct {
	Client     pb.AnonyEmailServerClient
	grpcClient *grpc.ClientConn
	timeOut    time.Duration
}

func NewTEEClientFromConfigFile(configFile string) (*TEEClient, error) {
	file, err := os.Open(configFile)
	if err != nil {
		log.Fatalf("fail to read from configuration file [%s]: %v", configFile, err)
	}
	defer file.Close()

	var conf config.Config
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&conf); err != nil {
		log.Fatalf("fail to decode configuration file [%s]: %v", configFile, err)
	}

	return NewTEEClient(&conf)
}

func NewTEEClient(conf *config.Config) (*TEEClient, error) {
	timeOut := time.Duration(conf.TimeOut)
	if conf.TimeOut < 30 {
		timeOut = time.Duration(config.DefaultTimeOut)
	}

	var conn *grpc.ClientConn
	if conf.TLS != nil {
		// Basic TLS
		caCert, err := ioutil.ReadFile(conf.TLS.CACert)
		if err != nil {
			return nil, fmt.Errorf("fail to load CA certificate for TEE client: [%v]", err)
		}
		certPool := x509.NewCertPool()
		config := &tls.Config{
			InsecureSkipVerify: false,
			RootCAs:            certPool,
			ServerName:         conf.TLS.HostName,
		}
		if !certPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("fail to append CA certificate for TEE client: [%v]", err)
		}

		if conf.TLS.Cert != "" && conf.TLS.PrivateKey != "" {
			// Mutual TLS
			peerCert, err := tls.LoadX509KeyPair(conf.TLS.Cert, conf.TLS.PrivateKey)
			if err != nil {
				return nil, fmt.Errorf("fail to load TEE client certificate: [%v]", err)
			}
			config.Certificates = []tls.Certificate{peerCert}
		}

		cred := credentials.NewTLS(config)
		conn, err = grpc.Dial(conf.Addr, grpc.WithTransportCredentials(cred))
		if err != nil {
			return nil, fmt.Errorf("fail to connect to TEE service: %v", err)
		}
	} else {
		var err error
		conn, err = grpc.Dial(conf.Addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, fmt.Errorf("fail to connect to TEE service: %v", err)
		}
	}

	return &TEEClient{
		Client:     pb.NewAnonyEmailServerClient(conn),
		grpcClient: conn,
		timeOut:    timeOut,
	}, nil
}

func (c *TEEClient) Close() error {
	return c.grpcClient.Close()
}

func (c *TEEClient) Attest(challenge []byte) (*pb.Response, error) {
	request := &pb.Request{
		Flag:    0,
		Message: challenge,
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeOut*time.Second)
	defer cancel()
	return c.Client.Attest(ctx, request)
}

func (c *TEEClient) SendAnonyEmail(encryptedAccount []byte, emailDomain, subject, content string) error {
	anonyEmail := &pb.AnonyEmail{
		EncryptedAddr:    []byte(emailDomain),
		EncryptedAccount: encryptedAccount,
		Subject:          []byte(subject),
		Content:          []byte(content),
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeOut*time.Second)
	defer cancel()
	res, err := c.Client.SendAnonyEmail(ctx, anonyEmail)
	if err != nil {
		return err
	}
	if res.Flag != 0 {
		return fmt.Errorf("fail to send e-mail to anonymous user accound: %s", string(res.Message))
	}

	return nil
}

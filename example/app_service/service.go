package app_service

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/FrozenFort/anonymous_email_client_go"
	"github.com/FrozenFort/anonymous_email_client_go/config"
	pb "github.com/FrozenFort/anonymous_email_client_go/pb/broker_anony_email"
)

const (
	testSubject   = "Test Authentication Code"
	allowedDomain = "gmail.com"
)

type CodeAndTime struct {
	Code  string
	Epoch time.Time
}

type AppService struct {
	pb.AnonyEmailBrokerServer

	Tee  *anonymous_email_client_go.TEEClient
	code sync.Map
}

func StartAppService(teeConfig *config.Config, appConfig *config.Config) {
	tee, err := anonymous_email_client_go.NewTEEClient(teeConfig)
	if err != nil {
		panic(err)
	}
	defer tee.Close()

	var s *grpc.Server
	if appConfig.TLS != nil {
		// Basic TLS
		peerCert, err := tls.LoadX509KeyPair(appConfig.TLS.Cert, appConfig.TLS.PrivateKey)
		if err != nil {
			panic("fail to load certificate and key: " + err.Error())
		}
		config := &tls.Config{
			Certificates:       []tls.Certificate{peerCert},
			InsecureSkipVerify: false,
		}

		// Mutual TLS
		if appConfig.TLS.CACert != "" {
			caCert, err := ioutil.ReadFile(appConfig.TLS.CACert)
			if err != nil {
				panic("fail to load CA certificate: " + err.Error())
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				panic("fail to append CA certificate: " + err.Error())
			}
			config.ClientCAs = caCertPool
			config.ClientAuth = tls.RequireAndVerifyClientCert
		}

		cred := credentials.NewTLS(config)
		s = grpc.NewServer(grpc.Creds(cred))
	} else {
		s = grpc.NewServer()
	}

	lis, err := net.Listen("tcp", appConfig.Addr)
	if err != nil {
		panic("failed to listen: " + err.Error())
	}

	brokerServer := &AppService{
		Tee: tee,
	}

	pb.RegisterAnonyEmailBrokerServer(s, brokerServer)

	fmt.Println("App starts...")
	if err := s.Serve(lis); err != nil {
		panic("failed to serve: " + err.Error())
	}
}

func (s *AppService) Attest(ctx context.Context, request *pb.Challenge) (*pb.Reply, error) {
	response, err := s.Tee.Attest(request.Message)
	if err != nil {
		return nil, err
	}
	return &pb.Reply{
		Flag:    response.Flag,
		Message: response.Message,
	}, nil
}

func (s *AppService) SendAnonyEmail(ctx context.Context, request *pb.AnonyEmailAddr) (*pb.Reply, error) {
	codeRaw := make([]byte, 5)
	_, err := rand.Read(codeRaw)
	if err != nil {
		return nil, err
	}
	code := base64.StdEncoding.EncodeToString(codeRaw)
	domain := string(request.EncryptedAddr)
	if domain != allowedDomain {
		return nil, fmt.Errorf("%v is not an allowed email domain", domain)
	}
	err = s.Tee.SendAnonyEmail(request.EncryptedAccount, domain, testSubject, code)
	if err != nil {
		errStr := fmt.Sprintf("fail to send authentication code: %v", err)
		return &pb.Reply{
			Flag:    1,
			Message: []byte(errStr),
		}, fmt.Errorf(errStr)
	}
	return &pb.Reply{
		Flag:    0,
		Message: []byte("please check your email box for authentication code"),
	}, nil
}

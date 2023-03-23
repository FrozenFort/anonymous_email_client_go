package app_client

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"gopkg.in/yaml.v3"

	"github.com/FrozenFort/anonymous_email_client_go/config"
	pb "github.com/FrozenFort/anonymous_email_client_go/pb/broker_anony_email"
)

const (
	AESKeySize                    = 16
	GCMNonceSize                  = 12
	DefaultChallengeLength uint32 = 32
	Uint32Size             uint32 = 4

	MinRSAPubKeySize uint32 = 400
	MinECCPubKeySize uint32 = 150
	MinECCSigSize    uint32 = 66

	MinProofSize uint32 = Uint32Size*4 + MinRSAPubKeySize + MinECCPubKeySize + MinECCSigSize
)

type TEEClient struct {
	Client     pb.AnonyEmailBrokerClient
	grpcClient *grpc.ClientConn
	timeOut    time.Duration

	TEEVerifyKey *ecdsa.PublicKey
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

	teeVKPEM, err := ioutil.ReadFile(conf.TEEVerifyKeyPath)
	if err != nil {
		return nil, fmt.Errorf("fail to read TEE verificaton key from file [%s]: %v",
			conf.TEEVerifyKeyPath, err)
	}
	teeVKBlock, _ := pem.Decode(teeVKPEM)
	teeVKGeneral, err := x509.ParsePKIXPublicKey(teeVKBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("fail to resolve TEE verification key from PEM: %v", err)
	}
	teeVK, ok := teeVKGeneral.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("configuration error: wrong TEE verification key type, "+
			"expect *ecdsa.Publickey, got %T", teeVKGeneral)
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
		Client:       pb.NewAnonyEmailBrokerClient(conn),
		grpcClient:   conn,
		timeOut:      timeOut,
		TEEVerifyKey: teeVK,
	}, nil
}

func (c *TEEClient) Close() error {
	return c.grpcClient.Close()
}

func (c *TEEClient) Attest() ([]byte, error) {
	challenge := make([]byte, 32)
	_, err := rand.Read(challenge)
	if err != nil {
		return nil, fmt.Errorf("attestation: fail to generate random challenge: %v", err)
	}
	request := &pb.Challenge{
		Flag:    0,
		Message: challenge,
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeOut*time.Second)
	defer cancel()
	proof, err := c.Client.Attest(ctx, request)
	if err != nil {
		return nil, err
	}
	if len(proof.Message) < int(MinProofSize)+len(challenge) {
		return nil, fmt.Errorf("invalid proof: proof should be at least %i bytes, got %i bytes",
			int(MinProofSize)+len(challenge), len(proof.Message))
	}

	cLen := binary.BigEndian.Uint32(proof.Message[:Uint32Size])
	if len(proof.Message) < int(Uint32Size+cLen) {
		return nil, fmt.Errorf("invalid proof: format mismatch")
	}
	challengeRec := proof.Message[Uint32Size : Uint32Size+cLen]
	if bytes.Compare(challenge, challengeRec) != 0 {
		return nil, fmt.Errorf("attestation: invalid proof, challenge mismatch")
	}

	ekLen := binary.BigEndian.Uint32(proof.Message[Uint32Size+cLen : Uint32Size*2+cLen])
	if len(proof.Message) < int(Uint32Size*2+cLen+ekLen) {
		return nil, fmt.Errorf("invalid proof: format mismatch")
	}
	ekPEM := proof.Message[Uint32Size*2+cLen : Uint32Size*2+cLen+ekLen]
	ekBlock, _ := pem.Decode(ekPEM)
	ekGeneral, err := x509.ParsePKIXPublicKey(ekBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("attestation: invalid encryption key: " + err.Error())
	}
	_, ok := ekGeneral.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("encryption key should be of type *rsa.PublicKey, got %T", ekGeneral)
	}

	vkLen := binary.BigEndian.Uint32(proof.Message[Uint32Size*2+cLen+ekLen : Uint32Size*3+cLen+ekLen])
	if len(proof.Message) < int(Uint32Size*3+cLen+ekLen+vkLen) {
		return nil, fmt.Errorf("invalid proof: format mismatch")
	}
	vkPEM := proof.Message[Uint32Size*3+cLen+ekLen : Uint32Size*3+cLen+ekLen+vkLen]
	vkBlock, _ := pem.Decode(vkPEM)
	vkGeneral, err := x509.ParsePKIXPublicKey(vkBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("attestation: invalid verification key: " + err.Error())
	}
	vk, ok := vkGeneral.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf(fmt.Sprintf("attestation: invalid verification key, expect *ecdsa.Publickey, got %T", vkGeneral))
	}

	if vk.X.Cmp(c.TEEVerifyKey.X) != 0 ||
		vk.Y.Cmp(c.TEEVerifyKey.Y) != 0 ||
		!vk.IsOnCurve(c.TEEVerifyKey.X, c.TEEVerifyKey.Y) {
		fmt.Printf("[%s] [%s]\n", vk.X.Text(16), c.TEEVerifyKey.X.Text(16))
		return nil, fmt.Errorf("attestation: remote service is not a trusted service")
	}
	//if vk != client.TEEVerifyKey {
	//	fmt.Printf("[%s] [%s]\n", vk.X.Text(16), client.TEEVerifyKey.X.Text(16))
	//	return nil, fmt.Errorf("attestation: remote service is not a trusted service")
	//}

	sigLen := binary.BigEndian.Uint32(proof.Message[Uint32Size*3+cLen+ekLen+vkLen : Uint32Size*4+cLen+ekLen+vkLen])
	if len(proof.Message) < int(Uint32Size*4+cLen+ekLen+vkLen+sigLen) {
		return nil, fmt.Errorf("invalid proof: format mismatch")
	}
	sig := proof.Message[Uint32Size*4+cLen+ekLen+vkLen : Uint32Size*4+cLen+ekLen+vkLen+sigLen]

	msg := proof.Message[:Uint32Size*3+cLen+ekLen+vkLen]
	dgst := sha256.Sum256(msg)
	ok = ecdsa.VerifyASN1(vk, dgst[:], sig)
	if !ok {
		return nil, fmt.Errorf("attestation: invalid signature from TEE service")
	}
	return ekPEM, nil
}

func (c *TEEClient) SendAnonyEmail(emailAddr, emailDomain string, ekPEM []byte) error {
	ekBlock, _ := pem.Decode(ekPEM)
	ekGeneral, err := x509.ParsePKIXPublicKey(ekBlock.Bytes)
	if err != nil {
		return fmt.Errorf("attestation: invalid encryption key: " + err.Error())
	}
	ek, ok := ekGeneral.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("encryption key should be of type *rsa.PublicKey, got %T", ekGeneral)
	}

	key := make([]byte, AESKeySize)
	_, err = rand.Read(key)
	if err != nil {
		return err
	}
	nonce := make([]byte, GCMNonceSize)
	_, err = rand.Read(nonce)
	if err != nil {
		return err
	}
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return err
	}
	encryptedAcc := gcm.Seal(nil, nonce, []byte(emailAddr), nil)
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, ek, key, nil)
	if err != nil {
		return err
	}
	ciphertext := append(append(encryptedKey, nonce...), encryptedAcc...)

	anonyEmail := &pb.AnonyEmailAddr{
		EncryptedAddr:    []byte(emailDomain),
		EncryptedAccount: ciphertext,
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeOut*time.Second)
	defer cancel()
	response, err := c.Client.SendAnonyEmail(ctx, anonyEmail)
	if err != nil {
		return err
	}
	if response.Flag != 0 {
		return fmt.Errorf("status: %v, message: %s", response.Flag, string(response.Message))
	}
	return nil
}

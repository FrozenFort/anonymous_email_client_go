package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	sdk "github.com/FrozenFort/anonymous_email_client_go"
)

func main() {
	client, err := sdk.NewTEEClientFromConfigFile("./config.yaml")
	if err != nil {
		panic(err)
	}
	challenge := make([]byte, 32)
	_, err = rand.Read(challenge)
	if err != nil {
		panic("attestation: fail to generate random challenge: " + err.Error())
	}
	proof, err := client.Attest(challenge)
	if err != nil {
		panic("attestation: fail to retrieve proof from remote server: " + err.Error())
	}
	if len(proof.Message) < len(challenge)+int(sdk.MinProofSize) {
		panic("attestation: invalid proof, length is too short")
	}

	cLen := binary.BigEndian.Uint32(proof.Message[:sdk.Uint32Size])
	challengeRec := proof.Message[sdk.Uint32Size : sdk.Uint32Size+cLen]
	if bytes.Compare(challenge, challengeRec) != 0 {
		panic("attestation: invalid proof, challenge mismatch")
	}

	ekLen := binary.BigEndian.Uint32(proof.Message[sdk.Uint32Size+cLen : sdk.Uint32Size*2+cLen])
	ekPEM := proof.Message[sdk.Uint32Size*2+cLen : sdk.Uint32Size*2+cLen+ekLen]
	ekBlock, _ := pem.Decode(ekPEM)
	ek, err := x509.ParsePKCS1PublicKey(ekBlock.Bytes)
	if err != nil {
		panic("attestation: invalid encryption key: " + err.Error())
	}

	vkLen := binary.BigEndian.Uint32(proof.Message[sdk.Uint32Size*2+cLen+ekLen : sdk.Uint32Size*3+cLen+ekLen])
	vkPEM := proof.Message[sdk.Uint32Size*3+cLen+ekLen : sdk.Uint32Size*3+cLen+ekLen+vkLen]
	vkBlock, _ := pem.Decode(vkPEM)
	vkGeneral, err := x509.ParsePKIXPublicKey(vkBlock.Bytes)
	if err != nil {
		panic("attestation: invalid verification key: " + err.Error())
	}
	vk, ok := vkGeneral.(*ecdsa.PublicKey)
	if !ok {
		panic(fmt.Sprintf("attestation: invalid verification key, expect *ecdsa.Publickey, got %T", vkGeneral))
	}
	if vk != client.TEEVerifyKey {
		panic("attestation: remote service is not a trusted service")
	}

	sigLen := binary.BigEndian.Uint32(proof.Message[sdk.Uint32Size*3+cLen+ekLen+vkLen : sdk.Uint32Size*4+cLen+ekLen+vkLen])
	sig := proof.Message[sdk.Uint32Size*4+cLen+ekLen+vkLen : sdk.Uint32Size*4+cLen+ekLen+vkLen+sigLen]

	msg := proof.Message[:sdk.Uint32Size*3+cLen+ekLen+vkLen]
	dgst := sha256.Sum256(msg)
	ok = ecdsa.VerifyASN1(vk, dgst[:], sig)
	if !ok {
		panic("attestation: invalid signature from TEE service")
	}

	key := []byte("1234567812345678")
	nonce := []byte("123456781234")
	userAcc := "zteragon"
	emailDomain := "gmail.com"
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		panic(err)
	}
	encryptedAcc := gcm.Seal(nil, nonce, []byte(userAcc), nil)
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, ek, key, nil)
	if err != nil {
		panic(err)
	}
	ciphertext := append(append(encryptedKey, nonce...), encryptedAcc...)
	err = client.SendAnonyEmail(ciphertext, emailDomain, "Test Subject", "This is a test.")
	if err != nil {
		panic(err)
	}
}

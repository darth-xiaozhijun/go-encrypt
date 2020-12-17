package myrsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
)

type MyRSA struct {
	Bits           int
	Decrypted      string
	PrivateKeyPath string
	PublicKeyPath  string
}

func (myRSA MyRSA) RsaEncrypt(originData []byte) ([]byte, error) {
	publicKey, _ := myRSA.getKey()
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, pub, originData)
}

func (myRSA MyRSA) RsaDecrypt(cipherData []byte) ([]byte, error) {
	_, privateKey := myRSA.getKey()
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, priv, cipherData)
}

func (myRSA MyRSA) RsaEncryptString(originText string) (string, error) {
	publicKey, _ := myRSA.getKey()
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return "", errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}
	pub := pubInterface.(*rsa.PublicKey)
	cipherData, err := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(originText))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(cipherData), nil
}

func (myRSA MyRSA) RsaDecryptString(cipherText string) (string, error) {
	_, privateKey := myRSA.getKey()
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return "", errors.New("private key error")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	cipherData, _ := base64.StdEncoding.DecodeString(cipherText)
	originData, err := rsa.DecryptPKCS1v15(rand.Reader, priv, cipherData)
	if err != nil {
		return "", err
	}
	return string(originData), nil
}

func (myRSA MyRSA) getKey() (publicKey []byte, privateKey []byte) {
	publicKey, err := ioutil.ReadFile(myRSA.PublicKeyPath)
	if err != nil {
		os.Exit(-1)
	}
	privateKey, err = ioutil.ReadFile(myRSA.PrivateKeyPath)
	if err != nil {
		os.Exit(-1)
	}
	return publicKey, privateKey
}

func (myRSA MyRSA) GenRsaKey() error {
	// 生成私钥文件
	privateKey, err := rsa.GenerateKey(rand.Reader, myRSA.Bits)
	if err != nil {
		return err
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "私钥",
		Bytes: derStream,
	}
	file, err := os.Create("private.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}

	// 生成公钥文件
	publicKey := &privateKey.PublicKey
	if err != nil {
		return err
	}
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	block = &pem.Block{
		Type:  "公钥",
		Bytes: derPkix,
	}
	file, err = os.Create("public.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	return nil
}

package myhash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
)

func HASH(text string, hashType string, isHex bool) string {
	var hashInstance hash.Hash
	switch hashType {
	case "md5":
		hashInstance = md5.New()
	case "sha1":
		hashInstance = sha1.New()
	case "sha256":
		hashInstance = sha256.New()
	case "sha512":
		hashInstance = sha512.New()
	}
	if isHex {
		arr, _ := hex.DecodeString(text)
		hashInstance.Write(arr)
	} else {
		hashInstance.Write([]byte(text))
	}
	cipherBytes := hashInstance.Sum(nil)
	return fmt.Sprintf("%x\n", cipherBytes)
}

func SHA256Double(text string, isHex bool) []byte {
	hashInstance := sha256.New()
	if isHex {
		arr, _ := hex.DecodeString(text)
		hashInstance.Write(arr)
	} else {
		hashInstance.Write([]byte(text))
	}
	cipherBytes := hashInstance.Sum(nil)
	hashInstance.Reset()
	hashInstance.Write(cipherBytes)
	cipherBytes = hashInstance.Sum(nil)
	return cipherBytes
}

func SHA256DoubleString(text string, isHex bool) string {
	hashInstance := sha256.New()
	if isHex {
		arr, _ := hex.DecodeString(text)
		hashInstance.Write(arr)
	} else {
		hashInstance.Write([]byte(text))
	}
	cipherBytes := hashInstance.Sum(nil)
	hashInstance.Reset()
	hashInstance.Write(cipherBytes)
	cipherBytes = hashInstance.Sum(nil)
	return fmt.Sprintf("%x\n", cipherBytes)
}

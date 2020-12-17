package main

import (
	"./myaes"
	"./myecdsa"
	"./myhash"
	"./myrsa"
	"./myutil"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
)

func main() {
	arr := []byte{'1', '0', '0', '0', 'p', 'h', 'o', 'n', 'e'}
	fmt.Println(string(arr))
	str := myutil.BytesToHexString(arr)
	fmt.Println(str)
	str = myutil.ReverseHexString(str)
	arr, _ = myutil.HexStringToBytes(str)
	fmt.Printf("%x\n", arr)
	myutil.ReverseBytes(arr)
	fmt.Println(string(arr))
	fmt.Println("----------------------------")

	str = "1000phone"
	fmt.Println(str)
	str1 := myhash.HASH(str, "md5", false)
	fmt.Println(str1)
	str2 := myhash.HASH(str, "sha1", false)
	fmt.Println(str2)
	str3 := myhash.HASH(str, "sha256", false)
	fmt.Println(str3)
	arr = myhash.SHA256Double(str, false)
	fmt.Println(string(arr))
	str4 := myhash.SHA256DoubleString(str, false)
	fmt.Println(str4)
	fmt.Println("----------------------------")

	str = "区块链很有趣"
	fmt.Println("AES加解密字节数组")
	key := []byte("1234567890abcdefghijklmnopqrstuv")
	resultArr, _ := myaes.AesEncrypt([]byte(str), key)
	fmt.Printf("加密后：%x\n", resultArr)
	resultArr, _ = myaes.AesDecrypt(resultArr, key)
	fmt.Println("解密后：", string(resultArr))
	fmt.Println("AES加解密字符串")
	cipherText, _ := myaes.AesEncryptString(str, key)
	fmt.Println("加密后：", cipherText)
	originalText, _ := myaes.AesDecryptString(cipherText, key)
	fmt.Println("解密后：", originalText)
	fmt.Println("----------------------------")

	var bits int
	flag.IntVar(&bits, "b", 2048, "密钥长度，默认为1024位")
	myRSA := myrsa.MyRSA{Bits: bits, Decrypted: "一篇诗，一斗酒，一曲长歌，一剑天涯", PrivateKeyPath: "./private.pem", PublicKeyPath: "./public.pem"}
	if err := myRSA.GenRsaKey(); err != nil {
		fmt.Println("密钥文件生成失败")
	}
	fmt.Println("密钥文件生成成功")
	fmt.Println("加密前：", myRSA.Decrypted)
	data, _ := myRSA.RsaEncryptString(myRSA.Decrypted)
	fmt.Println("加密后：", data)
	data, _ = myRSA.RsaDecryptString(data)
	fmt.Println("解密后：", data)

	fmt.Println("--------------------------生成签名--")
	privKey, pubKey := myecdsa.NewKeyPair()
	msg := sha256.Sum256([]byte("hello world"))
	r, s, _ := ecdsa.Sign(rand.Reader, &privKey, msg[:])
	strSigR := fmt.Sprintf("%x", r)
	strSigS := fmt.Sprintf("%x", s)
	fmt.Println("r,s的10进制分别为：", r, s)
	fmt.Println("r,s的16进制分别为：", strSigR, strSigS)
	signatureDer := myecdsa.MakeSignatureDerString(strSigR, strSigS)
	fmt.Println("数字签名的DER格式为：", signatureDer)
	res := myecdsa.VerifySig(pubKey, msg[:], r, s)
	fmt.Println("签名验证结果为：", res)
	res = myecdsa.VerifySignature(pubKey, msg[:], strSigR, strSigS)
	fmt.Println("签名验证结果为：", res)
}

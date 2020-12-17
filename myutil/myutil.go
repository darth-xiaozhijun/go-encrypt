package myutil

import "encoding/hex"

// 字节数组转十六进制字符串
func BytesToHexString(arr []byte) string {
	return hex.EncodeToString(arr)
}

// 十六进制字符串转字节数组
func HexStringToBytes(s string) (arr []byte, err error) {
	return hex.DecodeString(s)
}

// 十六进制字符串大端和小端颠倒
func ReverseHexString(hexStr string) string {
	arr, _ := hex.DecodeString(hexStr)
	ReverseBytes(arr)
	return hex.EncodeToString(arr)
}

// 字节数组大端和小端颠倒
func ReverseBytes(arr []byte) {
	for i, j := 0, len(arr)-1; i < j; i, j = i+1, j-1 {
		arr[i], arr[j] = arr[j], arr[i]
	}
}

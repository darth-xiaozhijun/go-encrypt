package myecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
)

func NewKeyPair() (ecdsa.PrivateKey, []byte) {
	curve := elliptic.P256()
	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Panic(err)
	}
	pubKey := append(private.X.Bytes(), private.Y.Bytes()...)
	return *private, pubKey
}

func MakeSignatureDerString(r, s string) string {
	lenSigR := len(r) / 2
	lenSigS := len(s) / 2
	lenSequence := lenSigR + lenSigS + 4
	strLenSigR := DecimalToHex(int64(lenSigR))
	strLenSigS := DecimalToHex(int64(lenSigS))
	strLenSequence := DecimalToHex(int64(lenSequence))
	derString := "30" + strLenSequence
	derString = derString + "02" + strLenSigR + r
	derString = derString + "02" + strLenSigS + s
	derString = derString + "01"
	return derString
}

func VerifySig(pubKey, message []byte, r, s *big.Int) bool {
	curve := elliptic.P256()
	keyLen := len(pubKey)
	x := big.Int{}
	y := big.Int{}
	x.SetBytes(pubKey[:(keyLen / 2)])
	y.SetBytes(pubKey[(keyLen / 2):])
	rawPubKey := ecdsa.PublicKey{curve, &x, &y}
	res := ecdsa.Verify(&rawPubKey, message, r, s)
	return res
}

func VerifySignature(pubKey, message []byte, r, s string) bool {
	curve := elliptic.P256()
	keyLen := len(pubKey)
	x := big.Int{}
	y := big.Int{}
	x.SetBytes(pubKey[:(keyLen / 2)])
	y.SetBytes(pubKey[(keyLen / 2):])
	rawPubKey := ecdsa.PublicKey{curve, &x, &y}
	rint := big.Int{}
	sint := big.Int{}
	rByte, _ := hex.DecodeString(r)
	sByte, _ := hex.DecodeString(s)
	rint.SetBytes(rByte)
	sint.SetBytes(sByte)
	res := ecdsa.Verify(&rawPubKey, message, &rint, &sint)
	return res
}

func DecimalToHex(n int64) string {
	if n < 0 {
		log.Println("the argument must be greater than zero")
		return ""
	}
	if n == 0 {
		return "0"
	}
	hex := map[int64]int64{10: 65, 11: 66, 12: 67, 13: 68, 14: 69, 15: 70}
	s := ""
	for q := n; q > 0; q = q / 16 {
		m := q % 16
		if m > 9 && m < 16 {
			m = hex[m]
			s = fmt.Sprintf("%v%v", string(m), s)
			continue
		}
		s = fmt.Sprintf("%v%v", m, s)
	}
	return s
}

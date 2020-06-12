package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"log"
)

func main(){
	priv, err := sm2.GenerateKey()
	if err != nil{
		log.Fatal(err)
	}
	pub := &priv.PublicKey

	msg := []byte("123456")
	d0, err := pub.Encrypt(msg)
	if err != nil {
		fmt.Printf("Error: failed to encrypt %s: %v\n", msg, err)
		return
	}
	fmt.Printf("encode string = [%d] %s\n", len(d0), hex.EncodeToString(d0))
	d1, err := priv.Decrypt(d0)
	if err != nil {
		fmt.Printf("Error: failed to decrypt: %v\n", err)
	}
	fmt.Printf("clear text = %s\n", d1)


	sign, err := priv.Sign(rand.Reader, msg, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("sign string = [%d] %s\n", len(sign),hex.EncodeToString(sign))

	x,y, err := sm2.SignDataToSignDigit(sign)
	fmt.Printf("x = %v, y = %v", x, y)
	sm2.Verify(pub, sign, x, y)


	ok := pub.Verify(msg, sign)
	if ok != true{
		fmt.Printf("verfiy fail")
	}




}
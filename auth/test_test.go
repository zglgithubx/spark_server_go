package auth

import (
	"fmt"
	"time"
	"testing"
)
func Test1(t *testing.T){
	time.Now()
	// timeStr := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
	fmt.Println("timeStr is", time.Now().UnixMilli())
}
func Test2(t *testing.T){
	//生成密钥对，保存到文件
	privateKey,publicKey:=GenerateRSAKey(1024)
	fmt.Println("私钥为：",privateKey)
	fmt.Println("公钥为：",publicKey)
	message:=[]byte("hello world")
	// //加密
	cipherText:=RSA_Encrypt(message,publicKey)
	fmt.Println("加密后为：",string(cipherText))
	//解密
	plainText := RSA_Decrypt(cipherText, privateKey)
	fmt.Println("解密后为：",string(plainText))
}
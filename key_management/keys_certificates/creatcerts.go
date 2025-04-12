package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

var nextNodeNum = 1

func main() {
	// 读取根证书文件
	rootCAFile := "RootCA.crt"
	rootCAKeyFile := "RootCA.key"
	rootCAData, err := os.ReadFile(rootCAFile)
	if err != nil {
		log.Fatalf("Failed to read root CA file: %v", err)
	}

	rootCAKeyData, err := os.ReadFile(rootCAKeyFile)
	if err != nil {
		log.Fatalf("Failed to read root CA key file: %v", err)
	}

	block, _ := pem.Decode(rootCAData)
	block2, _ := pem.Decode(rootCAKeyData)
	// 解析根证书和私钥
	rootCA, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse root CA certificate: %v", err)
	}
	rootCAKey, err := x509.ParsePKCS1PrivateKey(block2.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse root CA private key: %v", err)
	}

	// 创建一个随机数生成器
	rand := rand.Reader

	// 生成RSA密钥对
	privateKey, err := rsa.GenerateKey(rand, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// 定义证书模板
	template := x509.Certificate{
		SerialNumber: big.NewInt(int64(nextNodeNum)),
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("node_%d", nextNodeNum),
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0),

		// 使用 localhost 和 127.0.0.1 作为主机名和 IP 地址
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}

	nextNodeNum++

	// 使用根证书进行签名
	cert, err := x509.CreateCertificate(rand, &template, rootCA, privateKey.Public(), rootCAKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	// 将证书和私钥写入文件
	certOut, err := os.Create(fmt.Sprintf("node_%d.crt", nextNodeNum-1))
	if err != nil {
		log.Fatalf("Failed to open node.crt for writing: %v", err)
	}
	defer certOut.Close()

	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert})

	keyOut, err := os.OpenFile(fmt.Sprintf("node_%d.key", nextNodeNum-1), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open node.key for writing: %v", err)
	}
	defer keyOut.Close()

	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
}

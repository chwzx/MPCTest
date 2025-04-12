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

var nextNodeNum = 200

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
		SerialNumber: big.NewInt(0).SetBytes([]byte{0x7e, 0x8f, 0x11, 0xb6, 0xe9, 0xf9, 0x3c, 0x57, 0x03, 0x8c, 0x27, 0x6a, 0xda, 0xa9, 0x1e, 0x59}),
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("manager"),
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
	
		// 使用 localhost 和 127.0.0.1 作为主机名和 IP 地址
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		
				// 增强型密钥用法
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth, // 服务器身份验证 (1.3.6.1.5.5.7.3.1)
			x509.ExtKeyUsageClientAuth, // 客户端身份验证 (1.3.6.1.5.5.7.3.2)
		},
		
		// 使用者密钥标识符
		SubjectKeyId: []byte{0x2c, 0xba, 0x29, 0x54, 0xc8, 0x38, 0x49, 0xc2, 0x3c, 0xce, 0xb1, 0x3d, 0x25, 0x5b, 0x7d, 0x66, 0x97, 0xc1, 0xea, 0x52},
		
		// 密钥用法
		KeyUsage: x509.KeyUsageDigitalSignature | 
				  x509.KeyUsageKeyEncipherment | 
				  x509.KeyUsageDataEncipherment | 
				  x509.KeyUsageKeyAgreement, // 0xb8
	}

	nextNodeNum++

	// 使用根证书进行签名
	cert, err := x509.CreateCertificate(rand, &template, rootCA, privateKey.Public(), rootCAKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	// 将证书和私钥写入文件
	certOut, err := os.Create(fmt.Sprintf("Manager.crt"))
	if err != nil {
		log.Fatalf("Failed to open node.crt for writing: %v", err)
	}
	defer certOut.Close()

	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert})

	keyOut, err := os.OpenFile(fmt.Sprintf("Manager.key"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open node.key for writing: %v", err)
	}
	defer keyOut.Close()

	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
}

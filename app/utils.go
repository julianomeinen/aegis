package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"bytes"
)

const (
	blockSize = 16
	keySize = 256
)

func EncryptFile(publicKeyPath string, plainFilePath string, encryptedFilePath string)(bool) {

	content, err := ioutil.ReadFile(plainFilePath)
	if err != nil {
		panic(err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}

	pubKey, err := ReadPublicKey(publicKeyPath)
	if err != nil {
		panic(err)
	}
	// cipherKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, key, nil)
	cipherKey, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, key)
	if err != nil {
		panic(err)
	}

    iv := make([]byte, blockSize)
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        panic(err)
    }

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	content = Pkcs7Pad(content)
	
    ciphertext := make([]byte, len(content))

	mode := cipher.NewCBCEncrypter(block, iv)

	mode.CryptBlocks(ciphertext, content)
	
	cipherContent := ciphertext

	file, err := os.OpenFile(encryptedFilePath, os.O_RDWR|os.O_CREATE, 0644)
    if err != nil {
        panic(err)
    }
    defer file.Close()

    if err := file.Truncate(0); err != nil {
        panic(err)
    }

    _, err = file.Seek(0, 0)
    if err != nil {
        panic(err)
    }

	byteSlice := bytes.Join([][]byte{iv, cipherKey, cipherContent}, []byte{})

    if _, err := file.Write(byteSlice); err != nil {
        panic(err)
    }
	
	return true

}


func DecryptFile(privateKeyPath string, encryptedFilePath string, plainFilePath string) (bool) {

	privateKey, err := ReadPrivateKey(privateKeyPath)
	if err != nil {
		panic(err)
		return false
	}

	cipherBytes, err := os.ReadFile(encryptedFilePath)
	if err != nil {
		panic(err)
		return false
	}

	iv := cipherBytes[:blockSize]
	encryptedSessionKey := cipherBytes[blockSize:keySize+blockSize]
	encryptedContent := cipherBytes[(keySize+blockSize):]
	
	sessionKey, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptedSessionKey)

	if err != nil {
		fmt.Println("rsa.DecryptPKCS1v15 Error:", err)
		return false
	}

	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		fmt.Println("aes.NewCipher Error:", err)
		return false
	}

    mode := cipher.NewCBCDecrypter(block, iv)

    plaintext := make([]byte, len(encryptedContent))
    mode.CryptBlocks(plaintext, encryptedContent)

	plaintext = Pkcs7Unpad(plaintext)
	
	file, err := os.OpenFile(plainFilePath, os.O_RDWR|os.O_CREATE, 0644)
    if err != nil {
        panic(err)
    }
    defer file.Close()

    if err := file.Truncate(0); err != nil {
        panic(err)
    }

    _, err = file.Seek(0, 0)
    if err != nil {
        panic(err)
    }

    _, err = file.Write(plaintext)
    if err != nil {
        panic(err)
    }

	return true

}

func ReadPublicKey(filename string) (*rsa.PublicKey, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    content, err := ioutil.ReadAll(file)
    if err != nil {
        return nil, err
    }

    block, _ := pem.Decode(content)
    if block == nil {
        return nil, fmt.Errorf("failed to decode PEM block from public key file")
    }

    pkey, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return nil, err
    }

	rsaKey, ok := pkey.(*rsa.PublicKey)
	if !ok {
		fmt.Errorf("got unexpected key type: %T", pkey)
	}

    return rsaKey, nil
}

func ReadPrivateKey(filename string) (*rsa.PrivateKey, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    content, err := ioutil.ReadAll(file)
    if err != nil {
        return nil, err
    }

    block, _ := pem.Decode(content)
    if block == nil {
        return nil, fmt.Errorf("failed to decode PEM block from private key file")
    }

    privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
    if err != nil {
        return nil, err
    }

	rsaKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		fmt.Errorf("got unexpected key type: %T", privKey)
	}

    return rsaKey, nil
}

func Pkcs7Pad(data []byte) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func Pkcs7Unpad(data []byte) []byte {
	padding := int(data[len(data)-1])
	return data[:len(data)-padding]
}

func CompareFiles(file1, file2 string) (bool) {
    content1, err := ioutil.ReadFile(file1)
    if err != nil {
        panic(err)
    }

    content2, err := ioutil.ReadFile(file2)
    if err != nil {
        panic(err)
    }

	if bytes.Equal(content1, content2) != true {
		panic("The content of the files " + file1 + " and " + file2 + " is not the same.")
	}

	return true

}

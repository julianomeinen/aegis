package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

const (
	keySize = 32 // AES-256
	rsaSize = 256
)

func main() {
	
	// Encrypt the file
	encryptFile("./files/input.txt", "./files/input_encrypted.txt")

	// Decrypt the file
	decryptFile("./files/input_encrypted.txt", "./files/input_decrypted.txt")

}

func encryptFile(plainFilePath string, encryptedFilePath string) {
	// Ler o conteúdo do arquivo
	content, err := ioutil.ReadFile(plainFilePath)
	if err != nil {
		panic(err)
	}

	// Gerar uma chave de criptografia simétrica aleatória
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}

	// Criptografar a chave simétrica usando a chave pública RSA
	pubKey, err := readPublicKey("encrypt_key.pub")
	if err != nil {
		panic(err)
	}
	cipherKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, key, nil)
	if err != nil {
		panic(err)
	}

	// Criptografar o conteúdo do arquivo usando a chave simétrica
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	cipherContent := aesgcm.Seal(nil, nonce, content, nil)

	// Salvar a chave simétrica criptografada e o conteúdo do arquivo criptografado em um novo arquivo
	file, err := os.Create(encryptedFilePath)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	encoder := base64.NewEncoder(base64.StdEncoding, file)
	encoder.Write(cipherKey)
	encoder.Write(nonce)
	encoder.Write(cipherContent)
	encoder.Close()

	fmt.Println("cipherKey:", cipherKey)
	fmt.Println("nonce:", nonce)
	fmt.Println("cipherContent:", cipherContent)
	fmt.Println("key:", key)

	fmt.Println("Arquivo criptografado com sucesso")

}


func decryptFile(encryptedFilePath string, plainFilePath string) {
	
	// Lê a chave privada do arquivo PEM
	privateKey, err := readPrivateKey("encrypt_key")
	if err != nil {
		fmt.Println("Erro ao ler a chave privada:", err)
		return
	}

	// Lê o arquivo criptografado
	ciphertext, err := os.ReadFile(encryptedFilePath)
	if err != nil {
		fmt.Println("Erro ao ler o arquivo criptografado:", err)
		return
	}

	// Decodifica o arquivo
	cipherBytes, err := base64.StdEncoding.DecodeString(string(ciphertext))
	if err != nil {
		fmt.Println(err)
	}

	// Divide o arquivo criptografado em duas partes: a chave de sessão criptografada e o conteúdo criptografado
	encryptedSessionKey := cipherBytes[:rsaSize]
	encryptedNonce := cipherBytes[rsaSize:rsaSize+12]
	encryptedContent := cipherBytes[rsaSize+12:]

	fmt.Println("encryptedSessionKey:", encryptedSessionKey)
	fmt.Println("encryptedNonce:", encryptedNonce)
	fmt.Println("encryptedContent:", encryptedContent)
	
	sessionKey, err := rsa.DecryptOAEP(sha256.New(), nil, privateKey, encryptedSessionKey, nil)

	if err != nil {
		fmt.Println("Erro ao descriptografar a chave de sessão:", err)
		return
	}

	fmt.Println("key:", sessionKey)

	// Usa a chave de sessão para criar um cipher
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		fmt.Println("Erro ao criar um cipher:", err)
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, encryptedNonce, encryptedContent, nil)
	if err != nil {
		panic(err.Error())
	}

	// Grava o plaintext decifrado em um arquivo
	if err := ioutil.WriteFile(plainFilePath, plaintext, os.ModePerm); err != nil {
		panic(err)
	}

	fmt.Println("Arquivo descriptografado com sucesso!")

}

func readPublicKey(filename string) (*rsa.PublicKey, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    // Lê o conteúdo do arquivo
    content, err := ioutil.ReadAll(file)
    if err != nil {
        return nil, err
    }

    // Parseia a chave pública em formato PEM
    block, _ := pem.Decode(content)
    if block == nil {
        return nil, fmt.Errorf("failed to decode PEM block from public key file")
    }

    // Faz o parsing da chave pública RSA
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

func readPrivateKey(filename string) (*rsa.PrivateKey, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    // Lê o conteúdo do arquivo
    content, err := ioutil.ReadAll(file)
    if err != nil {
        return nil, err
    }

    // Parseia a chave privada em formato PEM
    block, _ := pem.Decode(content)
    if block == nil {
        return nil, fmt.Errorf("failed to decode PEM block from private key file")
    }

    // Faz o parsing da chave privada RSA
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

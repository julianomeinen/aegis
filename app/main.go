package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"bytes"
)

const (
	keySize = 16
	rsaSize = 256
)

func main() {
	
	// // Encrypt the file
	// encryptFile("./files/input.txt", "./files/input_encrypted.txt")

	// // Decrypt the file
	// decryptFile("./files/input_encrypted.txt", "./files/input_decrypted.txt")

	// // Encrypt the PDF file
	// encryptFile("./files/file.pdf", "./files/file_encrypted.pdf")

	// // Decrypt the PDF file
	// decryptFile("./files/file_encrypted.pdf", "./files/file_decrypted.pdf")

	// // Decrypt the PNG file
	decryptFile("./files/file-encrypted-php.png", "./files/file-decrypted-go.png")

	// same, err := compareFiles("./files/input.txt", "./files/input_decrypted.txt")
	// if err != nil {
	// 	panic(err)
	// }
	// if same != true {
	// 	panic("The content of the files is not the same.")
	// }
	
}

func encryptFile(plainFilePath string, encryptedFilePath string) {
	// Ler o conteúdo do arquivo
	content, err := ioutil.ReadFile(plainFilePath)
	if err != nil {
		panic(err)
	}

	// Gerar uma chave de criptografia simétrica aleatória
	key := make([]byte, 32)
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

	// Defina o vetor de inicialização (IV)
    iv := make([]byte, 16)
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        panic(err)
    }

	// Criptografar o conteúdo do arquivo usando a chave simétrica
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// Add padding if needed
	content = pkcs7Pad(content)
	
	// Crie um slice de bytes para armazenar o texto criptografado
    ciphertext := make([]byte, len(content))

	// Crie um cifrador de bloco CBC com o bloco AES-128-CBC e o vetor de inicialização
	mode := cipher.NewCBCEncrypter(block, iv)

	// Cifre o texto utilizando o método Ciphertext do cifrador de bloco CBC
	mode.CryptBlocks(ciphertext, content)
	
	cipherContent := ciphertext

	// Grava o plaintext decifrado em um arquivo
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

	// concatenate the byte slices
	byteSlice := bytes.Join([][]byte{iv, cipherKey, cipherContent}, []byte{})

    if _, err := file.Write(byteSlice); err != nil {
        panic(err)
    }
        
	fmt.Println("key:", key)
	fmt.Println("cipherContent:", len(cipherContent))
	
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
	cipherBytes, err := os.ReadFile(encryptedFilePath)
	if err != nil {
		fmt.Println("Erro ao ler o arquivo criptografado:", err)
		return
	}

	 iv := cipherBytes[:16]
	 encryptedSessionKey := cipherBytes[16:256+16]
	 encryptedContent := cipherBytes[(256+16):]
	
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

	// Define o modo de operação
    mode := cipher.NewCBCDecrypter(block, iv)

	// Descriptografa o texto cifrado
    plaintext := make([]byte, len(encryptedContent))
    mode.CryptBlocks(plaintext, encryptedContent)

	// Remove padding if needed
	plaintext = pkcs7Unpad(plaintext)
	
	// Grava o plaintext decifrado em um arquivo
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

func pkcs7Pad(data []byte) []byte {
	blockSize := 16
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func pkcs7Unpad(data []byte) []byte {
	padding := int(data[len(data)-1])
	return data[:len(data)-padding]
}

func compareFiles(file1, file2 string) (bool, error) {
    content1, err := ioutil.ReadFile(file1)
    if err != nil {
        return false, err
    }

    content2, err := ioutil.ReadFile(file2)
    if err != nil {
        return false, err
    }

    return bytes.Equal(content1, content2), nil
}

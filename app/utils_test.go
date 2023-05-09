package main

import (
    "testing"
)

func TestEncryptFile(t *testing.T) {
    
	result := EncryptFile("./tests/encrypt_key.pub", "./tests/files/input.txt", "./tests/files/input_encrypted.txt")
    expected := true
    if result != expected {
        t.Error("EncryptFile failed")
    }
}

func TestDecryptFile(t *testing.T) {
    
	result := DecryptFile("./tests/encrypt_key", "./tests/files/input_encrypted.txt", "./tests/files/input_decrypted.txt")
    expected := true
    if result != expected {
        t.Error("DecryptFile failed")
    }
}

func TestCompareFiles(t *testing.T) {
    
	result := CompareFiles("./tests/files/input.txt", "./tests/files/input_decrypted.txt")
    expected := true
    if result != expected {
        t.Error("CompareFiles failed")
    }
}

func TestEncryptAndDecryptPDF(t *testing.T) {
    
	result := EncryptFile("./tests/encrypt_key.pub", "./tests/files/file.pdf", "./tests/files/file_encrypted.pdf")
    expected := true
    if result != expected {
        t.Error("EncryptFile failed")
    }
	result = DecryptFile("./tests/encrypt_key", "./tests/files/file_encrypted.pdf", "./tests/files/file_decrypted.pdf")
    expected = true
    if result != expected {
        t.Error("DecryptFile failed")
    }
    result = CompareFiles("./tests/files/file.pdf", "./tests/files/file_decrypted.pdf")
    expected = true
    if result != expected {
        t.Error("CompareFiles failed")
    }
}

func TestDecryptPNGFromPy(t *testing.T) {
    
	result := DecryptFile("./tests/encrypt_key", "./tests/files/file-encrypted-py.png", "./tests/files/file-decrypted-py-go.png")
    expected := true
    if result != expected {
        t.Error("DecryptFile failed")
    }
    result = CompareFiles("./tests/files/file-decrypted-py-go.png", "./tests/files/file.png")
    expected = true
    if result != expected {
        t.Error("CompareFiles failed")
    }
}

func TestDecryptPNGFromPHP(t *testing.T) {
    
	result := DecryptFile("./tests/encrypt_key", "./tests/files/file-encrypted-php.png", "./tests/files/file-decrypted-php-go.png")
    expected := true
    if result != expected {
        t.Error("DecryptFile failed")
    }
    result = CompareFiles("./tests/files/file-decrypted-php-go.png", "./tests/files/file.png")
    expected = true
    if result != expected {
        t.Error("CompareFiles failed")
    }
}
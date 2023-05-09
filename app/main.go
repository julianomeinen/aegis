package main

func main() {
	
	// Encrypt the file
	EncryptFile("./tests/encrypt_key.pub", "./files/input.txt", "./files/input_encrypted.txt")

	// Decrypt the file
	// DecryptFile("./tests/encrypt_key", "./files/input_encrypted.txt", "./files/input_decrypted.txt")

	// // Encrypt the PDF file
	// EncryptFile("./tests/encrypt_key.pub", "./files/file.pdf", "./files/file_encrypted.pdf")

	// // Decrypt the PDF file
	// DecryptFile("./tests/encrypt_key", "./files/file_encrypted.pdf", "./files/file_decrypted.pdf")

	// // Decrypt the PNG file from PHP
	// DecryptFile("./tests/encrypt_key", "./files/file-encrypted-php.png", "./files/file-decrypted-php-go.png")

	// // Decrypt the PNG file from Py
	// DecryptFile("./tests/encrypt_key", "./files/file-encrypted-py.png", "./files/file-decrypted-py-go.png")

	// // Compare txt files after decrypt them
	// CompareFiles("./files/input.txt", "./files/input_decrypted.txt")

	// // Compare pdf files after decrypt them
	// CompareFiles("./files/file.pdf", "./files/file_decrypted.pdf")

	// // Compare png files after decrypt them
	// CompareFiles("./files/file.png", "./files/file-decrypted-php-go.png")
	// CompareFiles("./files/file.png", "./files/file-decrypted-py-go.png")
	
}

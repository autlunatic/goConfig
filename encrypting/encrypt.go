// Package encrypting provides a wrapper for a simple aes encryption using the CFBEncryption
package encrypting

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

const cEncryptedMarker = "[~enc~]"

// EncryptString Takes two strings, plainText and keyString.
// plainText is the text that needs to be encrypted by keyString.
// The function will output the resulting crypto text and an error variable.
func EncryptString(plainText string, keyString string) (cipherTextString string, err error) {
	key := sha256Sum(keyString)
	encrypted, err := encryptAES(key, []byte(cEncryptedMarker+plainText))
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(encrypted), nil
}

func encryptAES(key, data []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// create two 'windows' in to the output slice.
	output := make([]byte, aes.BlockSize+len(data))
	iv := output[:aes.BlockSize]
	encrypted := output[aes.BlockSize:]

	// populate the IV slice with random data.
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)

	// note that encrypted is still a window in to the output slice
	stream.XORKeyStream(encrypted, data)
	return output, nil
}

// DecryptString takes two strings, cryptoText and keyString.
// cryptoText is the text to be decrypted and the keyString is the key to use for the decryption.
// The function will output the resulting plain text string with an error variable.
func DecryptString(cryptoText string, keyString string) (plainTextString string, err error) {
	decrypted, err := decryptStringWithMarker(cryptoText, keyString)
	if err != nil {
		return cryptoText, err
	}
	return string(decrypted[len(cEncryptedMarker):]), nil

}

func decryptStringWithMarker(cryptoText string, keyString string) (plainTextString string, err error) {
	encrypted, err := base64.URLEncoding.DecodeString(cryptoText)
	if err != nil {
		return "", err
	}
	if len(encrypted) < aes.BlockSize {
		return "", fmt.Errorf("cipherText too short. It decodes to %v bytes but the minimum length is 16", len(encrypted))
	}
	decrypted, err := decryptAES(sha256Sum(keyString), encrypted)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

func decryptAES(key, data []byte) ([]byte, error) {
	// split the input up in to the IV seed and then the actual encrypted data.
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCFBDecrypter(block, iv)

	stream.XORKeyStream(data, data)
	return data, nil
}

// sha256Sum will compute a cryptographically useful hash of the input string.
func sha256Sum(input string) []byte {

	data := sha256.Sum256([]byte(input))
	return data[0:]

}

// IsEncrypted checks the cryptoText string if it is already crypted
// Therefore a encryptedMarker is used
func IsEncrypted(cryptoText string, keyString string) bool {
	decrypted, err := decryptStringWithMarker(cryptoText, keyString)
	if err != nil {
		return false
	}
	index := strings.Index(decrypted, cEncryptedMarker)
	return (index == 0)
}

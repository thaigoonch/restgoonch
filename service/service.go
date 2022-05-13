package restgoonch

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	"golang.org/x/net/context"
)

type Server struct {
	ServiceServer
}

func (s *Server) CryptoRequest(ctx context.Context, input *Request) (*DecryptedText, error) {
	log.Printf("Received text from client: %s", input.Text)

	encrypted, err := encrypt(input.Key, input.Text)
	if err != nil {
		return &DecryptedText{Result: ""},
			fmt.Errorf("error during encryption: %v", err)
	}
	result, err := decrypt(input.Key, encrypted)
	if err != nil {
		return &DecryptedText{Result: ""},
			fmt.Errorf("error during decryption: %v", err)
	}

	time.Sleep(4 * time.Second)
	return &DecryptedText{Result: result}, nil
}

func encrypt(key []byte, text string) (string, error) {
	plaintext := []byte(text)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func decrypt(key []byte, cryptoText string) (string, error) {
	ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return fmt.Sprintf("%v", ciphertext), nil
}

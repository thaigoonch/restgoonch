package restgoonch

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/gorilla/mux"
)

func CryptoRequest(resp http.ResponseWriter, req *http.Request) {
	//contentLength := req.ContentLength
	//fmt.Printf("Content Length Received : %v\n", contentLength)
	request := &Request{}
	data, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Fatalf("Unable to read message from request : %v", err)
	}
	proto.Unmarshal(data, request)

	text := request.GetText()
	key := request.GetKey()
	log.Printf("Received text from client: %s", text)

	msg := &DecryptedText{}
	encrypted, err := encrypt(key, text)
	if err != nil {
		msg = &DecryptedText{Result: fmt.Sprintf("error during encryption: %v", err)}
	} else {
		result, err := decrypt(key, encrypted)
		if err != nil {
			msg = &DecryptedText{Result: fmt.Sprintf("error during encryption: %v", err)}
		} else {
			msg = &DecryptedText{Result: result}
		}
	}
	response, err := proto.Marshal(msg)
	if err != nil {
		log.Fatalf("Unable to marshal response : %v", err)
	}
	time.Sleep(4 * time.Second)
	resp.Write(response)
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

func main() {
	fmt.Println("restgoonch waiting for client requests...")
	r := mux.NewRouter()
	r.HandleFunc("/cryptorequest", CryptoRequest).Methods("POST")

	server := &http.Server{
		Handler:      r,
		Addr:         "0.0.0.0:8080",
		WriteTimeout: 2 * time.Second,
		ReadTimeout:  2 * time.Second,
	}

	log.Fatal(server.ListenAndServe())
}

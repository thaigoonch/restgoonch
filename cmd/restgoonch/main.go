package main

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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	restgoonch "github.com/thaigoonch/restgoonch/service"
)

var (
	restPort     = 8080
	promPort     = 9092
	restReqCount = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "rest_server_handled_total",
		Help: "Total number of POSTs handled",
	})
)

func CryptoRequest(resp http.ResponseWriter, req *http.Request) {

	reg := prometheus.NewRegistry()
	_ = reg.Register(restReqCount)

	// Create an http server for prometheus
	httpServer := &http.Server{
		Handler: promhttp.HandlerFor(reg, promhttp.HandlerOpts{}),
		Addr:    fmt.Sprintf(":%d", promPort),
	}

	// Do REST service things
	request := &restgoonch.Request{}
	data, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Fatalf("Unable to read message from request : %v", err)
	}
	proto.Unmarshal(data, request)

	text := request.GetText()
	key := request.GetKey()
	log.Printf("Received text from client: %s", text)

	msg := &restgoonch.DecryptedText{}
	encrypted, err := encrypt(key, text)
	if err != nil {
		msg = &restgoonch.DecryptedText{Result: fmt.Sprintf("error during encryption: %v", err)}
	} else {
		result, err := decrypt(key, encrypted)
		if err != nil {
			msg = &restgoonch.DecryptedText{Result: fmt.Sprintf("error during encryption: %v", err)}
		} else { // Successful POST handled
			msg = &restgoonch.DecryptedText{Result: result}
		}
	}

	restReqCount.Inc()
	// Start http server for prometheus
	go func() {
		if err := httpServer.ListenAndServe(); err != nil {
			log.Fatalf("Unable to start an http server on port %d: %v", promPort, err)
		}
	}()

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
	r.HandleFunc("/service", CryptoRequest).Methods("POST")

	server := &http.Server{
		Handler:      r,
		Addr:         fmt.Sprintf(":%d", restPort),
		WriteTimeout: 6 * time.Second,
		ReadTimeout:  6 * time.Second,
	}

	log.Fatal(server.ListenAndServe())
}

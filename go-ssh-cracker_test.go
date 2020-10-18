package main

import "testing"
import "crypto/rsa"

//import "crypto/dsa"
import "crypto/rand"
import "crypto/ed25519"

func generateRSAPrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func generateED25519PrivateKey(bitSize int) (ed25519.PrivateKey, error) {
	// Private Key generation
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

//func checkKey(jobs <-chan string, results chan<- string, wg *sync.WaitGroup, block *pem.Block, keyType int) {
func TestCheckKey(t *testing.T) {
}

//func crack(block *pem.Block, wordlist string, factor int, keyType int) string {

//func usage() {

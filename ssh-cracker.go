/*
ssh-cracker - a simple ssh private key password recovery tool
Copyright (C) 2015 Athanasios Kostopoulos
*/
package main

import "fmt"
import "flag"
import "io/ioutil"
import "crypto/x509"
import "encoding/pem"
import "runtime"
import "strings"
import "os"

var workers = runtime.NumCPU()

type Job struct {
	password string
	results  chan<- Result
}

type Result struct {
	decrypted string
}

func (job Job) Do(block *pem.Block) {
	// casts []byte <-> string are cheap
	_, err := checkKey(block, []byte(job.password))
	if err == nil {
		job.results <- Result{(job.password)}
	}
}

func fatal(e error) {
	// Reading files requires checking most calls for errors.
	// This helper will streamline our error checks below.
	if e != nil {
		fmt.Println(e)
		panic(e)
	}
}

// channel housekeeping as described in "Programming in Go" pp 326-334
func processResults(results <-chan Result) {
	for result := range results {
		fmt.Println("Decrypted: %s", result.decrypted)
	}
	os.Exit(0)
}

func awaitCompletion(done <-chan struct{}, results chan Result) {
	for i := 0; i < workers; i++ {
		<-done
	}
	close(results)
}

func addJobs(jobs chan<- Job, block *pem.Block, passwords []string, results chan<- Result) {
	for _, password := range passwords {
		jobs <- Job{password, results}
	}
	close(jobs)
}

func doJobs(done chan<- struct{}, block *pem.Block, jobs <-chan Job) {
	for job := range jobs {
		job.Do(block)
	}
	done <- struct{}{}
}

func checkKey(block *pem.Block, password []byte) (string, error) {
	// https://github.com/golang/go/issues/10171
	// golang's fix? expand the documentation ...
	key, err := x509.DecryptPEMBlock(block, password)
	if err == nil {
		// we now have a candidate, is it random noise or is can be parsed?
		validKey := false
		_, err = x509.ParsePKCS8PrivateKey(key)
		if err == nil {
			validKey = true
		}
		// first try with RSA
		_, err = x509.ParsePKCS1PrivateKey(key)
		if err == nil {
			validKey = true
		}
		_, err = x509.ParseECPrivateKey(key)
		if err == nil {
			validKey = true
		}
		if validKey == true {
			return string(password), err
		}
	}
	return "", err
}

func extractPassword(wordlist string) []string {
	words, err := ioutil.ReadFile(wordlist)
	fatal(err)
	passwords := strings.Split(string(words), "\n")
	//fmt.Println(len(passwords))
	return passwords
}

func crack(block *pem.Block, wordlist string) {
	jobs := make(chan Job, workers)
	// there can be only one
	results := make(chan Result, 0x01)
	done := make(chan struct{}, workers)

	passwords := extractPassword(wordlist)
	// TODO: maybe this is stupid memory-wise
	go addJobs(jobs, block, passwords, results)
	for i := 0; i < workers; i++ {
		go doJobs(done, block, jobs)
	}
	go awaitCompletion(done, results)
	processResults(results)
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	keyPtr := flag.String("keyfile", "with_pass", "the keyfile you want to crack")
	wordPtr := flag.String("wordlist", "pass.txt", "the wordlist you want to use")
	flag.Parse()
	fmt.Println(*keyPtr)
	fmt.Println(*wordPtr)
	pemKey, err := ioutil.ReadFile(*keyPtr)
	fatal(err)
	block, _ := pem.Decode(pemKey)
	// first of all, is there even a password?
	if !x509.IsEncryptedPEMBlock(block) {
		fmt.Println("No pass detected - yay")
		os.Exit(0)
	}
	crack(block, *wordPtr)
}

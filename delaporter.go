/*
delaporter - a simple ssh private key password recovery tool
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
import "os/signal"
import "syscall"
import "golang.org/x/crypto/ssh"

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
		fmt.Printf("Decrypted: %s\n", result.decrypted)
		// this is a kludge
		os.Exit(0)
	}
}

func awaitCompletion(done <-chan struct{}, results chan Result) {
	for i := 0; i < workers; i++ {
		<-done
	}
	close(results)
}

func addJobs(jobs chan<- Job, block *pem.Block, passwords []string, results chan<- Result) {
	fmt.Println(".")
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
		_, err := ssh.ParseRawPrivateKey(key)
		if err == nil {
			return string(password), nil
		}
	}
	return "", err
}

func extractPassword(wordlist string) []string {
	fmt.Println("Loading wordlist")
	words, err := ioutil.ReadFile(wordlist)
	fatal(err)
	passwords := strings.Split(string(words), "\n")
	fmt.Println("Loaded ", len(passwords), " possible passwords")
	return passwords
}

func crack(block *pem.Block, wordlist string) {
	passwords := extractPassword(wordlist)
	for _, password := range passwords {
		candidate, err := checkKey(block, []byte(password))
		if err == nil && candidate != "" {
			fmt.Println("Pass found: ", candidate)
		}
		os.Stdout.Write([]byte("/"))
		os.Stdout.Write([]byte("\r"))
		os.Stdout.Write([]byte("-"))
		os.Stdout.Write([]byte("\r"))
		os.Stdout.Write([]byte("\\"))
		os.Stdout.Write([]byte("\r"))
		os.Stdout.Write([]byte("|"))
		os.Stdout.Write([]byte("\r"))
	}
}

func usage() {
	fmt.Println("delaporter -keyfile <SSH PRIVATE KEY> -wordfile <YOUR WORDLIST>")
	os.Exit(1)
}

func main() {
	os.Stdout.Write([]byte("\033[?25l"))
	// let us set a ^C handler ...
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)
	go func() {
		<-c
		os.Stdout.Write([]byte("\r"))
		os.Stdout.Write([]byte("\033[?25h"))
		os.Exit(255)
	}()
	runtime.GOMAXPROCS(runtime.NumCPU())
	keyPtr := flag.String("keyfile", "with_pass", "the keyfile you want to crack")
	wordPtr := flag.String("wordlist", "pass.txt", "the wordlist you want to use")
	flag.Parse()
	// a small sanity check
	if _, err := os.Stat(*keyPtr); err != nil {
		fmt.Printf("Keyfile %s not found - exiting\n", *keyPtr)
		usage()
	}
	if _, err := os.Stat(*wordPtr); err != nil {
		fmt.Printf("wordlist %s not found - exiting\n", *wordPtr)
		usage()
	}
	fmt.Printf("Cracking %s with wordlist %s\n", *keyPtr, *wordPtr)
	pemKey, err := ioutil.ReadFile(*keyPtr)
	fatal(err)
	block, _ := pem.Decode(pemKey)
	// first of all, is there even a password?
	if !x509.IsEncryptedPEMBlock(block) {
		fmt.Println("No pass detected - yay")
		os.Exit(0)
	}
	crack(block, *wordPtr)
	os.Stdout.Write([]byte("\033[?25h"))
}

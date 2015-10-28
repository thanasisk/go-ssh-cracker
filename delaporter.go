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
import "bufio"
import "os"
import "os/signal"
import "syscall"
import "golang.org/x/crypto/ssh"
import "sync"

var workers = runtime.NumCPU()

func fatal(e error) {
	// Reading files requires checking most calls for errors.
	// This helper will streamline our error checks below.
	if e != nil {
		fmt.Println(e)
		panic(e)
	}
}

func printNDie(pass []byte) {
	fmt.Println(string(pass))
	os.Exit(0)
}

func checkKey(jobs <-chan string, wg *sync.WaitGroup, block *pem.Block) {
	// https://github.com/golang/go/issues/10171
	// golang's fix? expand the documentation ...
	defer wg.Done()
	for passwordStr := range jobs {
		password := []byte(passwordStr)
		key, err := x509.DecryptPEMBlock(block, password)
		if err == nil {
			// we now have a candidate, is it random noise or is can be parsed?
			// for some reason ParseRawPrivateKey fails so its brute force time
			// https://github.com/golang/go/issues/8581 - ed25519 are not currently supported by Golang
			_, err := ssh.ParseDSAPrivateKey(key)
			if err == nil {
				printNDie(password)
			}
			// not DSA? maybe RSA
			_, err = x509.ParsePKCS1PrivateKey(key)
			if err == nil {
				printNDie(password)
			}
			// ECDSA?
			_, err = x509.ParseECPrivateKey(key)
			if err == nil {
				printNDie(password)
			}
		}
	}
}

func crack(block *pem.Block, wordlist string) string {
	jobs := make(chan string)
	file, err := os.Open(wordlist)
	if err != nil {
		fatal(err)
	}
	defer file.Close()
	wg := new(sync.WaitGroup)
	// Go over a file line by line and queue up a ton of work
	go func() {
		fmt.Println("Cracking ...")
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			jobs <- scanner.Text()
		}
		close(jobs)
	}()
	for w := 0; w < 512*workers; w++ {
		wg.Add(1)
		go checkKey(jobs, wg, block)
	}
	wg.Wait()
	return "Not found ..."
}

func usage() {
	fmt.Println("delaporter -keyfile <SSH PRIVATE KEY> -wordlist <YOUR WORDLIST>")
	os.Exit(1)
}

func main() {
	// let us set a ^C handler ...
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("^C caught - Exiting")
		os.Exit(255)
	}()
	runtime.GOMAXPROCS(workers)
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
	fmt.Println(crack(block, *wordPtr))
}

/*
delaporter - a simple ssh private key password recovery tool
Copyright (C) 2015-2016 Athanasios Kostopoulos
*/
package main

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/crypto/ssh"
)

var workers = runtime.NumCPU()

// just a shorthand
const (
	RSA     = iota
	DSA     = iota
	ECDSA   = iota
	ED25519 = iota
)

var keyTypes = map[string]int{
	// looks silly, eh?
	"rsa":   RSA,
	"dsa":   DSA,
	"ecdsa": ECDSA,
	// I love forward thinking
	"ed25519": ED25519,
}

const (
	NORMAL       = iota
	EUNSUPPORTED = iota
	EBADARGS     = iota
	EINT         = iota
)

func fatal(e error) {
	// Reading files requires checking most calls for errors.
	// This helper will streamline our error checks below.
	if e != nil {
		fmt.Println(e)
		panic(e)
	}
}

func checkKey(jobs <-chan string, results chan<- string, wg *sync.WaitGroup, block *pem.Block, keyType int) {
	// https://github.com/golang/go/issues/10171
	// golang's fix? expand the documentation ...
	defer wg.Done()
	for passwordStr := range jobs {
		password := []byte(passwordStr)
		key, err := x509.DecryptPEMBlock(block, password)
		if err == nil {
			// we now have a candidate, is it random noise or is can be parsed?
			// for some reason ParseRawPrivateKey fails so we try based on keyType
			// https://github.com/golang/go/issues/8581
			// ed25519 are not currently supported by Golang as part of stdlib
			switch keyType {
			case DSA:
				_, err := ssh.ParseDSAPrivateKey(key)
				if err == nil {
					//goto found is a possible fix for code duplication
					results <- string(password)
					close(results)
				}
			case RSA:
				_, err = x509.ParsePKCS1PrivateKey(key)
				if err == nil {
					results <- string(password)
					close(results)
				}
			case ECDSA:
				_, err = x509.ParseECPrivateKey(key)
				if err == nil {
					results <- string(password)
					close(results)
				}
			}
		}
	}
}

func crack(block *pem.Block, wordlist string, factor int, keyType int) string {
	jobs := make(chan string)
	results := make(chan string)
	// whatcha gonna do?
	file, err := os.Open(filepath.Clean(wordlist))
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
	for w := 0; w < factor*workers; w++ {
		wg.Add(1)
		go checkKey(jobs, results, wg, block, keyType)
	}
	select {
	case res := <-results:
		return res
	default:
	}
	wg.Wait()
	return "Not found ..."
}

func usage() {
	fmt.Printf("go-ssh-cracker -keyfile <SSH PRIVATE KEY>\n")
	fmt.Printf("-type rsa|dsa|ecdsa ed25519 coming soon\n")
	fmt.Printf("-wordlist <YOUR WORDLIST> -factor <1 <-> +oo>\n")
	fmt.Printf("optionally, you can enable -cpuprofile for profiling\n")
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
		os.Exit(EINT)
	}()
	runtime.GOMAXPROCS(workers)
	keyPtr := flag.String("keyfile", "with_pass", "the keyfile you want to crack")
	wordPtr := flag.String("wordlist", "pass.txt", "the wordlist you want to use")
	typePtr := flag.String("type", "rsa", "type of private key you want to crack")
	factorPtr := flag.Int("factor", 512, "performance factor")
	cpuprofile := flag.String("cpuprofile", "", "write cpu profile to file")
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
	if *factorPtr < 1 {
		fmt.Printf("performance factor %d should be more than 1 - exiting\n", *factorPtr)
		usage()
	}
	keyType := strings.ToLower(*typePtr)
	switch keyType {
	case "dsa":
		fallthrough
	case "rsa":
		fallthrough
	case "ecdsa":
		fmt.Printf("type %s supported - continuing\n", *typePtr)
	case "ed25519":
		fmt.Printf("Sorry %s is not supported yet\n", *typePtr)
		os.Exit(EUNSUPPORTED)
	default:
		fmt.Printf("Looks like you have had a crypto breakthrough\n")
		os.Exit(EBADARGS)
	}
	// is profiling enabled?
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			fatal(err)
		}
		// Start CPU profiling
		if err := pprof.StartCPUProfile(f); err != nil {
			panic(err)
		}
		defer pprof.StopCPUProfile()
	}
	fmt.Printf("Cracking %s with wordlist %s\n", *keyPtr, *wordPtr)
	pemKey, err := ioutil.ReadFile(*keyPtr)
	fatal(err)
	block, _ := pem.Decode(pemKey)
	// first of all, is there even a password?
	if !x509.IsEncryptedPEMBlock(block) {
		fmt.Println("No pass detected - yay")
		os.Exit(NORMAL)
	}
	fmt.Println(crack(block, *wordPtr, *factorPtr, keyTypes[keyType]))
}

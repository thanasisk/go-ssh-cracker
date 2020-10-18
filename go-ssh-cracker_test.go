package main

import "testing"
import "crypto/rsa"
import "crypto/x509"
import "encoding/pem"

//import "crypto/dsa"
import "crypto/rand"
import "crypto/ed25519"

//import "github.com/mattetti/filebuffer"
import "os"
import "io/ioutil"

// steals code from https://gist.github.com/devinodaniel/8f9b8a4f31573f428f29ec0e884e6673
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

func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey, pass string) ([]byte, error) {
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)
	privBlock := &pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}
	if pass != "" {
		var err error
		privBlock, err = x509.EncryptPEMBlock(rand.Reader, privBlock.Type, privBlock.Bytes, []byte(pass), x509.PEMCipherAES256)
		if err != nil {
			return nil, err
		}
	}
	privatePEM := pem.EncodeToMemory(privBlock)
	return privatePEM, nil
}

func generateED25519PrivateKey(bitSize int) (ed25519.PrivateKey, error) {
	// Private Key generation
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func TestCrack(t *testing.T) {
	testKey, err := generateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal("could not create RSA key")
	}
	testPEM, err := encodePrivateKeyToPEM(testKey, "shouldPass")
	if err != nil {
		t.Fatal("Could not encode RSA key to PEM")
	}
	tests := []struct {
		name string
		pass string
		want bool
	}{
		{
			name: "failing RSA testcase",
			pass: "should fail",
			want: false,
		},
		{
			name: "passing RSA testcase",
			pass: "shouldPass",
			want: true,
		},
	}
	for _, tt := range tests {
		tmpFile, err := ioutil.TempFile("./", "wlist")
		if err != nil {
			t.Fatal("failed to create temporary file for testing")
		}
		tmpFile.Write([]byte(tt.pass))
		defer os.Remove(tmpFile.Name())
		foo, _ := pem.Decode(testPEM)
		res := crack(foo, tmpFile.Name(), 512, RSA)
		t.Log("res: " + res)
		if tt.want != true && tt.pass == res {
			t.Errorf("pass guessed for invalid pass: " + tt.name)
		}
		if (tt.want == true && tt.pass == res) || (tt.want == false && tt.pass != res) {
			t.Log("proper behavior for: " + tt.name)
		}
	}
}

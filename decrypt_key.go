package main

import (
    "encoding/hex"
    "crypto/rsa"
    "crypto/rand"
    "crypto/sha256"
    "math/big"
    "fmt"
    "log"
    "os"
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
            N: fromBase10(""), // yes, yes change all of those
            E: 65537,
        },
        D: fromBase10(""),
        Primes: []*big.Int{
            fromBase10(""),
            fromBase10(""),
        },
    }
    Key.Precompute()
}

func main() {
    key, err := hex.DecodeString(os.Args[1])
    if err != nil {
        log.Fatal(err)
    }
    aes_key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, &Key, key, nil)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Key: %x\n", aes_key)
}

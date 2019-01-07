package main

import (
    "crypto/rsa"
    "crypto/rand"
    "fmt"
    "log"
)

func main() {
    keys, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("[*] Public Key")
    fmt.Println("Modulus (N):", keys.PublicKey.N)
    fmt.Println("Exponent(E):", keys.PublicKey.E)

    fmt.Println("[*] Private Key")
    fmt.Println("Private Exponent (D):", keys.D)
    fmt.Println("Primes (P):", keys.Primes) // there are two
}
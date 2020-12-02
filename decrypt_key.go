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
            N: fromBase10("28173238234479268692748171777584780950112726971800472303179518822064257035330343535382062519135554178057392050439512475197418759177681714996439478119637798431181217850091954574573450965244968320132378502502291379125779591047483820406235123169703702675102086669837722293492775826594973909630373982606134840347804878462514286834694538401513937386496705419688029997745683837628079207343818814366116867188449488550233959271590182601502875729623298406808420521843821837320643772450775606353905712230611517533654282258147082226740950169620818579409805061640251994478022087950933425934855126618181491816001603975662267491029"), // yes, yes change all of those
            E: 65537,
        },
        D: fromBase10("1305253570522749035381407052020700831573420707454991440776110792368184439879358561979958747377073762162376359655606630276666960319990158097619500242834677317799037669686348195290864231896078510008360786229880942283589492535475763673946804163757440109135487827572642571367809256485501614077707318360422466938477802404213170830852628424515204600948803732143633145200903165106154288222680859148759161133044967943865679519559675906017857950720239241628963170748497204675265825430928983091974528975876690706137199694211759249687334161846122106581962825964353784848097176644907960038139277797372679101725556050292503945357130525357052274903538140705202070083157342070745499144077611079236818443987935856197995874737707376216237635965560663027666696031999015809761950024283467731779903766968634819529086423189607851000836078622988094228358949253547576367394680416375744010913548782757264257136780925648550161407770731836042246693847780240421317083085262842451520460094880373214363314520090316510615428822268085914875916113304496794386567951955967590601785795072023924162896317074849720467526582543092898309197452897587669070613719969421175924968733416184612210658196282596435378484809717664490796003813927779737267910172555605029250394535733"),
        Primes: []*big.Int{
            fromBase10("160803121333994197109393236454483826601157235065418104973594680803448050337606271455343999037534246720860929592009049824199942564451893226446637463997113918702301731460176102024266264784288654748363727800821141671230524345484900375041561795874030903441587597634330212912703667181331154286588955401740963032051"),
            fromBase10("175203304517717548961257849098262659002438085654365857455555635248359514793705390774215497938364418743009679986407704640197786599827954540228278686953100138490259703518415344365625777686407611061773887342891903751914332234928888431598063202786326483260607112989813048341608084603529101060754160655066174509079"),
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

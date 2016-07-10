# tools
    Include some encrypt and decrypt tools, use algorithm like des, 3des, aes. Some abstract algorithm also contained in this package.

## supported encrypt and decrypt algorithm
    aes, des, 3des, base64
## supported abstract algorithm
    md5_16, md5_32, sha1
## demo
encrypt file

```
package main

import (
	"log"
	"time"

	"github.com/Tom-kail/tools"
)

func main() {
	log.Println("start")
	EB := time.Now().UnixNano()
	//  `myfile.txt` is a file waiting to be encrypted, `cipher.txt` is encrypt output, 10240 byte is buffer size
	err := tools.EncryptFile("myfile.txt", "cipher.txt", "aes", []byte("your_key"), 10240)
	if err != nil {
		log.Fatal(err)
	}
	EF := time.Now().UnixNano()
	DB := time.Now().UnixNano()
	err = tools.DecryptFile("cipher.txt", "clear.txt", "aes", []byte("your_key"), 10240)
	if err != nil {
		log.Fatal(err)
	}
	DF := time.Now().UnixNano()
	log.Println("finish")
	EC := float64(EF-EB) / 1000000000
	DC := float64(DF-DB) / 1000000000
	log.Println("\t\nEncrypt cost: ", EC, "\t\nDecrypt cost: ", DC)

}
```

Encrypt byte array
```Go
func Encrypt(data []byte, typ string, key []byte) ([]byte, error) {
	....
}

func Decrypt(data []byte, typ string, key []byte) ([]byte, error) {
	....
}

```

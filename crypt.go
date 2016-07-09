package tools

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

type CryptReq struct {
	Data        []byte `form:"data"`
	EncryptType string `form:"encryptType"`
	Key         []byte `form:"key"`
}

const (
	base64Table = "123QRSTUabcdVWXYZHijKLAWDCABDstEFGuvwxyzGHIJklmnopqr234560178912"
)

var coder = base64.NewEncoding(base64Table)

func md5Encrypt(content []byte, bitLen int) ([]byte, error) {
	if bitLen != 16 && bitLen != 32 {
		return nil, errors.New("位长只能是16位或32位")
	}

	h := md5.New()
	h.Write(content) // 需要加密的字符串为 sharejs.com
	longCipher := hex.EncodeToString(h.Sum(nil))
	if bitLen == 32 {
		return []byte(strings.ToUpper(longCipher)), nil
	} else {
		shortCipher := longCipher[8:24]
		return []byte(strings.ToUpper(shortCipher)), nil
	}
}

// 3DES加密
func tripleDesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	origData = pkcs5Padding(origData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key[:8])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

// 3DES解密
func tripleDesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key[:8])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = pkcs5UnPadding(origData)
	return origData, nil
}

func desEncrypt(origData, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	origData = pkcs5Padding(origData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key)
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

//des解密
func desDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key)
	origData := crypted
	blockMode.CryptBlocks(origData, crypted)
	origData = ZeroUnPadding(origData)
	return origData, nil
}

func pkcs5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func pkcs5UnPadding(origData []byte) []byte {
	length := len(origData)
	// 去掉最后一个字节 unpadding 次
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func ZeroUnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func getKey(strKey string) []byte {
	keyLen := len(strKey)
	if keyLen < 16 {
		panic("res key 长度不能小于16")
	}
	arrKey := []byte(strKey)
	if keyLen >= 32 {
		//取前32个字节
		return arrKey[:32]
	}
	if keyLen >= 24 {
		//取前24个字节
		return arrKey[:24]
	}
	//取前16个字节
	return arrKey[:16]
}

//加密字符串
func aesEncrypt(strMesg []byte, strKey string) ([]byte, error) {
	if len(strKey) < 16 {
		return nil, errors.New("The key length cannot be less than 128 bit")
	}
	key := getKey(strKey)
	var iv = []byte(key)[:aes.BlockSize]
	encrypted := make([]byte, len(strMesg))
	aesBlockEncrypter, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesEncrypter := cipher.NewCFBEncrypter(aesBlockEncrypter, iv)
	aesEncrypter.XORKeyStream(encrypted, strMesg)
	return encrypted, nil
}

//解密字符串
func aesDecrypt(origData []byte, strKey string) (rst []byte, err error) {
	key := getKey(strKey)
	var iv = []byte(key)[:aes.BlockSize]
	decrypted := make([]byte, len(origData))
	var aesBlockDecrypter cipher.Block
	aesBlockDecrypter, err = aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	aesDecrypter := cipher.NewCFBDecrypter(aesBlockDecrypter, iv)
	aesDecrypter.XORKeyStream(decrypted, origData)
	return decrypted, nil
}

func base64Encode(originDataStr string) ([]byte, error) {
	tmpCipher := base64.StdEncoding.EncodeToString([]byte(originDataStr))
	return []byte(tmpCipher), nil
}

func base64Decode(originDataStr string) ([]byte, error) {
	tmpCipher, cryErr := base64.StdEncoding.DecodeString(originDataStr)
	if cryErr != nil {
		return nil, errors.New("Base64字符串格式不正确")
	}
	return tmpCipher, cryErr
}

func sha1Encrypt(origData string) ([]byte, error) {
	t := sha1.New()
	_, err := io.WriteString(t, origData)
	if err != nil {
		return nil, err
	} else {
		return []byte(fmt.Sprintf("%x", t.Sum(nil))), nil
	}
}

func EncryptData(req CryptReq) ([]byte, error) {
	cipher := []byte{}
	var err error
	switch req.EncryptType {
	case "md5_16":
		cipher, err = md5Encrypt(req.Data, 16)
	case "md5_32":
		cipher, err = md5Encrypt(req.Data, 32)
	case "sha1":
		cipher, err = sha1Encrypt(string(req.Data))
	case "aes":
		MD5Key, genKeyErr := md5Encrypt(req.Key, 16)
		if genKeyErr != nil {
			return nil, genKeyErr
		}
		cipher, err = aesEncrypt(req.Data, string(MD5Key))
	case "des":
		MD5Key, genKeyErr := md5Encrypt(req.Key, 16)
		if genKeyErr != nil {
			return nil, genKeyErr
		}
		cipher, err = desEncrypt(req.Data, MD5Key[0:8])
	case "3des":
		MD5Key, genKeyErr := md5Encrypt(req.Key, 32)
		if genKeyErr != nil {
			return nil, genKeyErr
		}
		cipher, err = tripleDesEncrypt(req.Data, MD5Key[0:24])
	case "base64":
		cipher, err = base64Encode(string(req.Data))
	default:
		return nil, errors.New("encrypt type is not supported")
	}
	return cipher, err
}

func DecryptData(req CryptReq) ([]byte, error) {
	clearText := []byte{}
	var err error
	switch req.EncryptType {
	case "aes":
		MD5Key, genKeyErr := md5Encrypt(req.Key, 16)
		if genKeyErr != nil {
			return nil, genKeyErr
		}
		clearText, err = aesDecrypt(req.Data, string(MD5Key))
	case "des":

		MD5Key, genKeyErr := md5Encrypt(req.Key, 16)
		if genKeyErr != nil {
			return nil, genKeyErr
		}
		clearText, err = desDecrypt(req.Data, MD5Key[0:8])
	case "3des":
		MD5Key, genKeyErr := md5Encrypt(req.Key, 32)
		if genKeyErr != nil {
			return nil, genKeyErr
		}
		clearText, err = tripleDesDecrypt(req.Data, MD5Key[0:24])
	case "base64":
		clearText, err = base64Decode(string(req.Data))
	default:
		return nil, errors.New("decrypt type is not supported")
	}
	return clearText, err

}

func Encrypt(data []byte, typ string, key []byte) ([]byte, error) {
	req := CryptReq{
		Data:        data,
		EncryptType: typ,
		Key:         key,
	}
	return EncryptData(req)
}

func Decrypt(data []byte, typ string, key []byte) ([]byte, error) {
	req := CryptReq{
		Data:        data,
		EncryptType: typ,
		Key:         key,
	}
	return DecryptData(req)
}

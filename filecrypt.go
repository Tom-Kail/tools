package tools

import (
	"bufio"
	"errors"
	"io"
	"os"
)

func EncryptFile(src, dst, typ string, key []byte, bufSize int) error {
	sf, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sf.Close()
	df, err2 := os.Create(dst)
	if err != nil {
		return err2
	}
	defer df.Close()
	buf := make([]byte, bufSize) //一次读取多少个字节
	bfRd := bufio.NewReader(sf)
	bfwr := bufio.NewWriter(df)
	for {
		n, err := bfRd.Read(buf)
		if err != nil { //遇到任何错误立即返回，并忽略 EOF 错误信息
			if err == io.EOF {
				return nil
			}
			return err
		}
		//log.Println("read ", n, " bytes")

		cipher, EncryptErr := Encrypt(buf[:n], typ, key)
		if EncryptErr != nil {
			return EncryptErr
		}

		_, err3 := bfwr.Write(cipher)
		bfwr.Flush()
		//log.Println("write ", nn, " bytes")
		if err3 != nil {

			return errors.New("Err: " + err3.Error() + "\ndata: " + string(cipher))
		}

	}
	return nil
}

func DecryptFile(src, dst, typ string, key []byte, bufSize int) error {
	sf, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sf.Close()
	df, err2 := os.Create(dst)
	if err != nil {
		return err2
	}
	defer df.Close()
	buf := make([]byte, bufSize) //一次读取多少个字节
	bfRd := bufio.NewReader(sf)
	bfwr := bufio.NewWriter(df)
	for {
		n, err := bfRd.Read(buf)
		if err != nil { //遇到任何错误立即返回，并忽略 EOF 错误信息
			if err == io.EOF {
				return nil
			}
			return err
		}

		cipher, DecryptErr := Decrypt(buf[:n], typ, key)
		if DecryptErr != nil {
			return errors.New("Decrypt: " + DecryptErr.Error())
		}

		_, err3 := bfwr.Write(cipher)
		bfwr.Flush()

		if err3 != nil {
			return errors.New("Err: " + err3.Error() + "\ndata: " + string(cipher))
		}

	}
	return nil
}

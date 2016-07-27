package tools

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"unsafe"
)

var version = int32(0)

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

func getfileinfos(filename string) (buf *bytes.Buffer, filelen int64, err error) {
	buf = new(bytes.Buffer)

	err = binary.Write(buf, binary.LittleEndian, int32(len(filename)))
	if err != nil {
		return buf, filelen, err
	}

	n, err := buf.Write([]byte(filename))
	if err != nil {
		return buf, filelen, err
	}
	if n < len(filename) {
		return buf, filelen, errors.New("buf write filename error")
	}

	info, err := os.Stat(filename)
	filelen = info.Size()
	err = binary.Write(buf, binary.LittleEndian, filelen)
	if err != nil {
		return buf, filelen, err
	}

	return buf, filelen, nil
}

func encodefile(inputfile, outputfile string, passkey []byte) error {
	in, err := os.Open(inputfile)
	if err != nil {
		fmt.Printf("%s open error\n", inputfile)
		return err
	}

	out, err := os.Create(outputfile)
	if err != nil {
		fmt.Printf("%s create error\n", outputfile)
		return err
	}

	//===============write version number
	err = binary.Write(out, binary.LittleEndian, version)
	if err != nil {
		fmt.Printf("version write error\n")
		return err
	}

	//===============write encoded random key
	key := make([]byte, 32)
	n, err := io.ReadFull(rand.Reader, key)
	if n < 32 || err != nil {
		fmt.Printf("key error\n")
		return err
	}
	c, err := aes.NewCipher(passkey[0:32])
	if err != nil {
		fmt.Printf("pass cipher create error\n")
		return err
	}
	b := make([]byte, 32)
	c.Encrypt(b[0:16], key[0:16])
	c.Encrypt(b[16:32], key[16:32])
	out.Write(b)
	c, err = aes.NewCipher(key)
	if err != nil {
		fmt.Printf("cipher create error\n", outputfile)
		return err
	}

	//===============write encoded file infos
	buf, filelen, err := getfileinfos(inputfile)
	if err != nil {
		fmt.Print("getfileinfos error:", err)
		return err
	}

	b = make([]byte, c.BlockSize())
	for n, err := buf.Read(b); err == nil && n > 0; n, err = buf.Read(b) {
		c.Encrypt(b, b)
		out.Write(b)
	}

	//===============write encoded file
	for n, err := in.Read(b); n != 0 && err != io.EOF && filelen > 0; n, err = in.Read(b) {
		c.Encrypt(b, b)
		out.Write(b)
		filelen -= int64(c.BlockSize())
	}

	defer in.Close()
	defer out.Close()
	fmt.Print("encrypt finished\n")
	return nil
}

func EncryptFileByAES(src, dsc, key string) error {
	return encodefile(src, dsc, getpasskey(key))
}
func DecryptFileByAES(src, dsc, key string) error {
	return decodefile(src, dsc, getpasskey(key))
}

func decodefile(inputfile, outputfile string, passkey []byte) error {
	in, err := os.Open(inputfile)
	if err != nil {
		fmt.Printf("%s open error\n", inputfile)
		return err
	}

	//===============read version 0
	var fileversion int32
	err = binary.Read(in, binary.LittleEndian, &fileversion)
	if err != nil {
		fmt.Printf("version read error\n")
		return err
	}
	if fileversion != version {
		fmt.Printf("file version error")
		return err
	}

	//===============read decoded random key
	key := make([]byte, 32)
	n, err := in.Read(key)
	if n < 32 || err != nil {
		fmt.Printf("key error")
		return err
	}
	c, err := aes.NewCipher(passkey[0:32])
	if err != nil {
		fmt.Printf("cipher create error\n")
		return err
	}
	c.Decrypt(key[0:16], key[0:16])
	c.Decrypt(key[16:32], key[16:32])
	c, err = aes.NewCipher(key)
	if err != nil {
		fmt.Printf("cipher create error\n")
		return err
	}

	//===============read length of file name
	b := make([]byte, c.BlockSize())
	n, err = in.Read(b)
	if n < c.BlockSize() || err != nil {
		fmt.Printf("read file len error")
		return err
	}
	c.Decrypt(b, b)
	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, b)
	if err != nil {
		fmt.Print(err)
		return err
	}
	var filenamelen int32
	binary.Read(buf, binary.LittleEndian, &filenamelen)

	//===============read file name and file length
	var filelen int64
	filename := make([]byte, filenamelen)
	infolen := filenamelen + int32(unsafe.Sizeof(filenamelen)) + int32(unsafe.Sizeof(filelen)) - int32(c.BlockSize())
	if infolen > 0 {
		for n, err = in.Read(b); n > 0 && err != io.EOF; n, err = in.Read(b) {
			c.Decrypt(b, b)
			err = binary.Write(buf, binary.LittleEndian, b)
			if err != nil {
				fmt.Print(err)
				return err
			}
			infolen -= int32(c.BlockSize())
			if infolen <= 0 {
				break
			}
		}
	}
	if infolen > 0 {
		return errors.New("may be it is not an eccrypted file?")
	}
	binary.Read(buf, binary.LittleEndian, &filename)
	binary.Read(buf, binary.LittleEndian, &filelen)

	//===============create file with file name
	//os.MkdirAll(outputfile, 0777)
	//	out, err := os.Create(outputdir + string(filename))

	out, err := os.Create(outputfile)
	if err != nil {
		return err
	}

	//===============decrypt file content
	for n, err := in.Read(b); n != 0 && err != io.EOF; n, err = in.Read(b) {
		c.Decrypt(b, b)
		if filelen > int64(c.BlockSize()) {
			filelen -= int64(c.BlockSize())
			out.Write(b)
		} else {
			out.Write(b[0:filelen])
		}
	}

	if filelen > int64(c.BlockSize()) {
		fmt.Print("may be it is not an eccrypted file?\n")
		return err
	}

	//===============decrypt finished
	defer in.Close()
	defer out.Close()

	fmt.Print("decrypt finished\n")
	return nil
}

func getpasskey(key string) []byte {
	b, err := Encrypt([]byte(key), "md5_32", nil)
	if err != nil {
		panic(err)
	}
	return b
}

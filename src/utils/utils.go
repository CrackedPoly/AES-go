package utils

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

type PaddingFunc func([]byte, int) []byte

type UnpaddingFunc func([]byte) []byte

func ReadStringHex(filename string) string {
	f, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("Error in reading", filename, err)
	}
	return string(f)
}

func WriteStringHex(filename string, msg string) {
	err := ioutil.WriteFile(filename, []byte(msg), 0666)
	if err != nil {
		fmt.Println("Error in writing", filename, err)
	}
}

func ReadBytesHex(filename string) []byte {
	tmp, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("Error in reading", filename, err)
	}
	if len(tmp)%2 == 1 { // add an '0' to the [-2] position.
		tmp = append(tmp[:len(tmp)-1], byte('0'), tmp[len(tmp)-1])
	}
	hexStringReader := strings.NewReader(string(tmp))
	tmp2 := make([]byte, len(tmp)/2)
	_, err = fmt.Fscanf(hexStringReader, "%x", &tmp2)
	return tmp2
}

func WriteBytesHex(filename string, msg []byte) {
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		fmt.Println("Open file err =", err)
		return
	}
	defer file.Close()

	_, err = fmt.Fprintf(file, "%x", msg)
	if err != nil {
		return
	}
	return
}

func DumpWords(note string, in []uint32) {
	fmt.Printf("%s", note)
	for i, v := range in {
		if i%4 == 0 {
			fmt.Printf("\nword[%02d]: %.8x ", i/4, v)
		} else {
			fmt.Printf("%.8x ", v)
		}
	}
	fmt.Println("\n")
}

func DumpBytes(note string, in []byte) {
	fmt.Printf("%s", note)
	for i, v := range in {
		if i%16 == 0 {
			fmt.Printf("\nblock[%d]: %02x", i/16, v)
		} else {
			if i%4 == 0 {
				fmt.Printf(" %02x", v)
			} else {
				fmt.Printf("%02x", v)
			}
		}
	}
	fmt.Println("\n")
}

func ZeroPadding(in []byte, blockLen int) []byte {
	tmp := make([]byte, len(in))
	copy(tmp, in)

	remainder := len(tmp) % blockLen
	for i := 0; i < blockLen-remainder; i++ {
		tmp = append(tmp, 0x00)
	}
	return tmp
}

func ZeroUnpadding(in []byte) []byte {
	for in[len(in)-1] == 0x00 {
		in = in[:len(in)-1]
	}
	tmp := make([]byte, len(in))
	copy(tmp, in)
	return tmp
}

func PKCS7Padding(in []byte, blockLen int) []byte {
	tmp := make([]byte, len(in))
	copy(tmp, in)

	rmd := len(tmp) % blockLen
	for i := 0; i < blockLen-rmd; i++ {
		tmp = append(tmp, byte(blockLen-rmd))
	}
	return tmp
}

func PKCS7Unpadding(in []byte) []byte {
	last := int(in[len(in)-1])
	tmp := make([]byte, len(in)-last)
	copy(tmp, in[:len(in)-last])
	return tmp
}

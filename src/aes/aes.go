package aes

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/CrackedPoly/AES-implementation-in-Golang/src/utils"
	"math"
	"math/big"
	"reflect"
)

var sbox = [256]byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

var inv_sbox = [256]byte{
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
}

var rcon = [10]uint32{
	0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
	0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000,
}

type AES struct {
	nr        int      // number of rounds
	nk        int      // number of words in the key
	nb        int      // number of words in a block
	len       int      // length(byte) of block
	key       []byte   // key
	roundKeys []uint32 // round keys generated from key.
}

// NewAES returns a pointer of type AES and an error.
//
// key: The following algorithms will be used based on the size of the key:
//
// 16 bytes = AES-128
//
// 24 bytes = AES-192
//
// 32 bytes = AES-256
func NewAES(key []byte) (*AES, error) {
	var nk, nr int
	switch len(key) {
	case 16:
		nk = 4
		nr = 10
	case 24:
		nk = 6
		nr = 12
	case 32:
		nk = 8
		nr = 14
	default:
		return nil, errors.New("invalid key length")
	}
	aes := AES{
		nr:  nr,
		nk:  nk,
		nb:  4,
		len: 16,
		key: key,
	}
	aes.roundKeys = aes.keyExpansion()
	return &aes, nil
}

// keyExpansion returns an uint32 slice presenting round keys
// (4 uint32 for a key) in encryption. The number of round keys
// is determined by the type of encryption. For example, 11 round
// keys in AES-128.
func (a *AES) keyExpansion() []uint32 {
	var w []uint32
	for i := 0; i < a.nk; i++ { // little-endian or big-endian matters.
		w = append(w, binary.BigEndian.Uint32(a.key[4*i:4*i+4]))
	}
	for i := a.nk; i < a.nb*(a.nr+1); i++ {
		tempW := make([]byte, 4)
		binary.BigEndian.PutUint32(tempW, w[i-1])
		if i%a.nk == 0 {
			rotWord(tempW)
			a.subBytes(tempW)
			tempRcon := make([]byte, 4)
			binary.BigEndian.PutUint32(tempRcon, rcon[i/a.nk-1])
			Xor(tempW, tempRcon)
		} else if a.nk > 6 && i%a.nk == 4 {
			a.subBytes(tempW)
		}
		w = append(w, w[i-a.nk]^binary.BigEndian.Uint32(tempW))
	}

	utils.DumpWords("keyExpansion:", w)
	return w
}

// EncryptECB returns the cipher of ECB-mode encryption.
func (a *AES) EncryptECB(in []byte, pad utils.PaddingFunc) []byte {
	in = pad(in, a.len)

	for i := 0; i < len(in); i += a.len {
		a.encryptBlock(in[i:i+a.len], a.roundKeys)
	}

	fmt.Printf("aes_impl-%d ECB encrypted cipher:", a.nk*32)
	utils.DumpBytes("", in)
	return in
}

// DecryptECB returns the plaintext of ECB-mode decryption.
func (a *AES) DecryptECB(in []byte, unpad utils.UnpaddingFunc) []byte {
	for i := 0; i < len(in); i += a.len {
		a.decryptBlock(in[i:i+a.len], a.roundKeys)
	}

	in = unpad(in)
	fmt.Printf("aes_impl-%d ECB decrypted plaintext:", a.nk*32)
	utils.DumpBytes("", in)
	return in
}

// EncryptCBC returns the cipher of CBC-mode encryption.
// The iv must be 128bit.
func (a *AES) EncryptCBC(in []byte, iv []byte, pad utils.PaddingFunc) []byte {
	in = pad(in, a.len)
	ivTmp := make([]byte, len(iv))
	copy(ivTmp, iv)

	for i := 0; i < len(in); i += a.len {
		Xor(in[i:i+a.len], ivTmp)
		a.encryptBlock(in[i:i+a.len], a.roundKeys)
		copy(ivTmp, in[i:i+a.len])
	}

	fmt.Printf("aes_impl-%d CBC encrypted cipher:", a.nk*32)
	utils.DumpBytes("", in)
	return in
}

// DecryptCBC returns the plaintext of CBC-mode decryption.
// The iv must be 128bit.
func (a *AES) DecryptCBC(in []byte, iv []byte, unpad utils.UnpaddingFunc) []byte {
	ivTmp := make([]byte, len(iv))
	copy(ivTmp, iv)
	reg := make([]byte, a.len)

	for i := 0; i < len(in); i += a.len {
		copy(reg, in[i:i+a.len])
		a.decryptBlock(in[i:i+a.len], a.roundKeys)
		Xor(in[i:i+a.len], ivTmp)
		copy(ivTmp, reg)
	}

	in = unpad(in)
	fmt.Printf("aes_impl-%d CBC decrypted plaintext:", a.nk*32)
	utils.DumpBytes("", in)
	return in
}

// EncryptCFB encrypts every s bytes of plaintext, with
// s at least 1 and no more than 128.
// The iv must be 128bit.
func (a *AES) EncryptCFB(in []byte, iv []byte, s int) []byte {
	ivTmp := make([]byte, a.len)
	copy(ivTmp, iv)

	i := 0
	for ; i < len(in)-s; i += s {
		a.encryptBlock(ivTmp, a.roundKeys)
		Xor(in[i:i+s], ivTmp[0:s])
		ivTmp = append(ivTmp[s:], in[i:i+s]...)
	}
	a.encryptBlock(ivTmp, a.roundKeys)
	Xor(in[i:], ivTmp[0:s]) // process on the last bytes (less than s)

	fmt.Printf("aes_impl-%d CFB with %d-bytes shift encrypted cipher:", a.nk*32, s)
	utils.DumpBytes("", in)
	return in
}

// DecryptCFB decrypts every s bytes of ciphertext, with
// s at least 1 and no more than 128.
// The iv must be 128bit.
func (a *AES) DecryptCFB(in []byte, iv []byte, s int) []byte {
	ivTmp := make([]byte, len(iv))
	copy(ivTmp, iv)
	cipherTmp := make([]byte, len(in))
	copy(cipherTmp, in)

	i := 0
	for ; i < len(in)-s; i += s {
		a.encryptBlock(ivTmp, a.roundKeys)
		Xor(in[i:i+s], ivTmp[0:s])
		ivTmp = append(ivTmp[s:], cipherTmp[i:i+s]...)
	}
	a.encryptBlock(ivTmp, a.roundKeys)
	Xor(in[i:], ivTmp[0:s])

	fmt.Printf("aes_impl-%d CFB with %d-bytes shift decrypted plaintext:", a.nk*32, s)
	utils.DumpBytes("", in)
	return in
}

// EncryptOFB returns the cipher of OFB-mode encryption.
// The iv must be 128bit.
func (a *AES) EncryptOFB(in []byte, iv []byte) []byte {
	ivTmp := make([]byte, len(iv))
	copy(ivTmp, iv)

	i := 0
	for ; i < len(in)-a.len; i += a.len {
		a.encryptBlock(ivTmp, a.roundKeys)
		Xor(in[i:i+a.len], ivTmp)
	}
	a.encryptBlock(ivTmp, a.roundKeys)
	Xor(in[i:], ivTmp)

	fmt.Printf("aes_impl-%d OFB encrypted cipher:", a.nk*32)
	utils.DumpBytes("", in)
	return in
}

// DecryptOFB returns the plaintext of OFB-mode decryption.
// The iv must be 128bit.
func (a *AES) DecryptOFB(in []byte, iv []byte) []byte {
	ivTmp := make([]byte, len(iv))
	copy(ivTmp, iv)

	i := 0
	for ; i < len(in)-a.len; i += a.len {
		a.encryptBlock(ivTmp, a.roundKeys)
		Xor(in[i:i+a.len], ivTmp)
	}
	a.encryptBlock(ivTmp, a.roundKeys)
	Xor(in[i:], ivTmp)

	fmt.Printf("aes_impl-%d OFB decrypted plaintext:", a.nk*32)
	utils.DumpBytes("", in)
	return in
}

// EncryptCTR returns the ciphertext of CTR-mode encryption.
// The iv must be 128bit.
func (a *AES) EncryptCTR(in []byte, iv []byte) []byte {
	ivTmp := make([]byte, len(iv))
	copy(ivTmp, iv)
	ivNumber := big.NewInt(0).SetBytes(iv)
	one := big.NewInt(1)

	i := 0
	for ; i < len(in)-a.len; i += a.len {
		a.encryptBlock(ivTmp, a.roundKeys)
		Xor(in[i:i+a.len], ivTmp)
		ivNumber.Add(ivNumber, one).FillBytes(ivTmp)
	}
	a.encryptBlock(ivTmp, a.roundKeys)
	Xor(in[i:], ivTmp)

	fmt.Printf("aes_impl-%d CTR encrypted ciphertext:", a.nk*32)
	utils.DumpBytes("", in)
	return in
}

// DecryptCTR returns the plaintext of CTR-mode decryption.
// The iv must be 128bit.
// It is exactly the same with EncryptCTR.
func (a *AES) DecryptCTR(in []byte, iv []byte) []byte {
	ivTmp := make([]byte, len(iv))
	copy(ivTmp, iv)
	ivNumber := big.NewInt(0).SetBytes(iv)
	one := big.NewInt(1)

	i := 0
	for ; i < len(in)-a.len; i += a.len {
		a.encryptBlock(ivTmp, a.roundKeys)
		Xor(in[i:i+a.len], ivTmp)
		ivNumber.Add(ivNumber, one).FillBytes(ivTmp)
	}
	a.encryptBlock(ivTmp, a.roundKeys)
	Xor(in[i:], ivTmp)

	fmt.Printf("aes_impl-%d CTR decrypted ciphertext:", a.nk*32)
	utils.DumpBytes("", in)
	return in
}

// EncryptGCM returns the ciphertext of GCM-mode encryption and the tag.
func (a *AES) EncryptGCM(in []byte, iv []byte, auth []byte, tagLen int) ([]byte, []byte) {
	H := make([]byte, 16)
	a.encryptBlock(H, a.roundKeys)
	var J0 []byte

	if len(iv) == 12 {
		J0 = append(iv, []byte{0x00, 0x00, 0x00, 0x01}...)
	} else {
		sPlus64Zeros := make([]byte, 16*int(math.Ceil(float64(8*len(iv))/128.0))-len(iv)+8)
		lenIV := make([]byte, 8)
		big.NewInt(int64(8 * len(iv))).FillBytes(lenIV)
		J0 = gHash(append(append(iv, sPlus64Zeros...), lenIV...), H)
	}
	J0Tmp := make([]byte, len(J0))
	copy(J0Tmp, J0)

	in = a.EncryptGCTR(in, inc32(J0))
	vZeros := make([]byte, 16*int(math.Ceil(float64(8*len(auth))/128.0))-len(auth))
	uZeros := make([]byte, 16*int(math.Ceil(float64(8*len(in))/128.0))-len(in))
	lenA := make([]byte, 8)
	lenC := make([]byte, 8)
	big.NewInt(int64(8 * len(auth))).FillBytes(lenA)
	big.NewInt(int64(8 * len(in))).FillBytes(lenC)
	S := gHash(append(append(append(append(append(auth, vZeros...), in...), uZeros...), lenA...), lenC...), H)
	T := a.EncryptGCTR(S, J0Tmp)
	fmt.Printf("aes_impl-%d GCM encrypted ciphertext:", a.nk*32)
	utils.DumpBytes("", in)
	utils.DumpBytes("tag:", T[:tagLen])
	return in, T[:tagLen]
}

// DecryptGCM returns the plaintext of GCM-mode decryption or
// a nil if authentication failed.
func (a *AES) DecryptGCM(in []byte, iv []byte, auth []byte, tag []byte) []byte {
	H := make([]byte, 16)
	a.encryptBlock(H, a.roundKeys)
	var J0 []byte

	if len(iv) == 12 {
		J0 = append(iv, []byte{0x00, 0x00, 0x00, 0x01}...)
	} else {
		sPlus64Zeros := make([]byte, 16*int(math.Ceil(float64(8*len(iv))/128.0))-len(iv)+8)
		lenIV := make([]byte, 8)
		big.NewInt(int64(8 * len(iv))).FillBytes(lenIV)
		J0 = gHash(append(append(iv, sPlus64Zeros...), lenIV...), H)
	}
	J0Tmp := make([]byte, len(J0))
	copy(J0Tmp, J0)

	ciphertext := make([]byte, len(in))
	copy(ciphertext, in)
	in = a.EncryptGCTR(in, inc32(J0))
	vZeros := make([]byte, 16*int(math.Ceil(float64(8*len(auth))/128.0))-len(auth))
	uZeros := make([]byte, 16*int(math.Ceil(float64(8*len(in))/128.0))-len(in))
	lenA := make([]byte, 8)
	lenC := make([]byte, 8)
	big.NewInt(int64(8 * len(auth))).FillBytes(lenA)
	big.NewInt(int64(8 * len(in))).FillBytes(lenC)
	S := gHash(append(append(append(append(append(auth, vZeros...), ciphertext...), uZeros...), lenA...), lenC...), H)
	T := a.EncryptGCTR(S, J0Tmp)
	fmt.Printf("aes_impl-%d GCM decrypted plaintext:", a.nk*32)
	if reflect.DeepEqual(T[:len(tag)], tag) {
		utils.DumpBytes("", in)
		return in
	}
	utils.DumpBytes("\nFailed", nil)
	return nil
}

// subBytes operation in AES encryption.
func (a *AES) subBytes(state []byte) {
	for i, v := range state {
		state[i] = sbox[v]
	}
}

// invSubBytes operation in AES decryption.
func (a *AES) invSubBytes(state []byte) {
	for i, v := range state {
		state[i] = inv_sbox[v]
	}
}

func (a *AES) shiftRow(in []byte, i int, n int) {
	in[i], in[i+4*1], in[i+4*2], in[i+4*3] = in[i+4*(n%4)], in[i+4*((n+1)%4)], in[i+4*((n+2)%4)], in[i+4*((n+3)%4)]
}

// rotWord rotates a 4-byte slice leftward. That is in << 8.
func rotWord(in []byte) {
	in[0], in[1], in[2], in[3] = in[1], in[2], in[3], in[0]
}

// shiftRows operation in AES encryption.
func (a *AES) shiftRows(state []byte) {
	a.shiftRow(state, 1, 1)
	a.shiftRow(state, 2, 2)
	a.shiftRow(state, 3, 3)
}

// invShiftRows operation in AES decryption.
func (a *AES) invShiftRows(state []byte) {
	a.shiftRow(state, 1, 3)
	a.shiftRow(state, 2, 2)
	a.shiftRow(state, 3, 1)
}

// xtime returns the result of multiplication by x in GF(2^8).
func xtime(in byte) byte {
	return (in << 1) ^ (((in >> 7) & 1) * 0x1b)
}

// xtimes returns the result of multiplication by x^ts in GF(2^8).
func xtimes(in byte, ts int) byte {
	for ts > 0 {
		in = xtime(in)
		ts--
	}
	return in
}

// mulByte returns byte x multiplied by byte y in GF(2^8).
func mulByte(x byte, y byte) byte {
	return (((y >> 0) & 0x01) * xtimes(x, 0)) ^
		(((y >> 1) & 0x01) * xtimes(x, 1)) ^
		(((y >> 2) & 0x01) * xtimes(x, 2)) ^
		(((y >> 3) & 0x01) * xtimes(x, 3)) ^
		(((y >> 4) & 0x01) * xtimes(x, 4)) ^
		(((y >> 5) & 0x01) * xtimes(x, 5)) ^
		(((y >> 6) & 0x01) * xtimes(x, 6)) ^
		(((y >> 7) & 0x01) * xtimes(x, 7))
}

// mulWord provides the one-column mix for the function
// mixColumns and invMixColumns. In fact, it's a matrix
// multiplication.
func mulWord(x []byte, y []byte) {
	tmp := make([]byte, 4)
	copy(tmp, x)

	x[0] = mulByte(tmp[0], y[3]) ^ mulByte(tmp[1], y[0]) ^ mulByte(tmp[2], y[1]) ^ mulByte(tmp[3], y[2])
	x[1] = mulByte(tmp[0], y[2]) ^ mulByte(tmp[1], y[3]) ^ mulByte(tmp[2], y[0]) ^ mulByte(tmp[3], y[1])
	x[2] = mulByte(tmp[0], y[1]) ^ mulByte(tmp[1], y[2]) ^ mulByte(tmp[2], y[3]) ^ mulByte(tmp[3], y[0])
	x[3] = mulByte(tmp[0], y[0]) ^ mulByte(tmp[1], y[1]) ^ mulByte(tmp[2], y[2]) ^ mulByte(tmp[3], y[3])
}

// mixColumns operation in AES encryption.
func (a *AES) mixColumns(state []byte) {
	s := []byte{0x03, 0x01, 0x01, 0x02}
	for i := 0; i < len(state); i += 4 {
		mulWord(state[i:i+4], s)
	}
}

// invMixColumns operation in AES decryption.
func (a *AES) invMixColumns(state []byte) {
	s := []byte{0x0b, 0x0d, 0x09, 0x0e}
	for i := 0; i < len(state); i += 4 {
		mulWord(state[i:i+4], s)
	}
}

// Xor applies y xor to x. Please make sure that len(y) >= len(x).
func Xor(x []byte, y []byte) {
	if len(x) <= len(y) {
		for i := 0; i < len(x); i++ {
			x[i] = x[i] ^ y[i]
		}
	}
}

// addRoundKey operation in AES.
func (a *AES) addRoundKey(state []byte, w []uint32) {
	tmp := make([]byte, a.len)
	for i := 0; i < len(w); i += 1 {
		binary.BigEndian.PutUint32(tmp[4*i:4*i+4], w[i])
	}
	Xor(state, tmp)
}

// encryptBlock encrypts one block in the plaintext.
func (a *AES) encryptBlock(state []byte, roundKeys []uint32) {
	a.addRoundKey(state, roundKeys[0:4])
	for round := 1; round < a.nr; round++ {
		a.subBytes(state)
		a.shiftRows(state)
		a.mixColumns(state)
		a.addRoundKey(state, roundKeys[4*round:4*round+4])
	}
	a.subBytes(state)
	a.shiftRows(state)
	a.addRoundKey(state, roundKeys[a.nr*4:a.nr*4+4])
}

// decryptBlock decrypts one block in the ciphertext.
func (a *AES) decryptBlock(state []byte, roundKeys []uint32) {
	a.addRoundKey(state, roundKeys[a.nr*4:a.nr*4+4])
	for round := a.nr - 1; round > 0; round-- {
		a.invShiftRows(state)
		a.invSubBytes(state)
		a.addRoundKey(state, roundKeys[4*round:4*round+4])
		a.invMixColumns(state)
	}
	a.invShiftRows(state)
	a.invSubBytes(state)
	a.addRoundKey(state, roundKeys[0:4])
}

// inc increments the right-most 32 bits of the bit string X,
// and it returns X.
func inc32(X []byte) []byte {
	lsb32 := binary.BigEndian.Uint32(X[len(X)-4:]) + 1
	binary.BigEndian.PutUint32(X[len(X)-4:], lsb32)
	return X
}

// mulBlock impose a multiplication operation to x in GCM mode.
func mulBlock(x []byte, y []byte) {
	tmp := big.NewInt(0).SetBytes([]byte{0xe1})

	R := tmp.Lsh(tmp, 120)
	X := big.NewInt(0).SetBytes(x)
	Z := big.NewInt(0)
	V := big.NewInt(0).SetBytes(y)
	for i := 0; i < 128; i++ {
		if X.Bit(127-i) == 1 {
			Z.Xor(Z, V)
		}
		if V.Bit(0) == 0 {
			V.Rsh(V, 1)
		} else {
			V.Xor(V.Rsh(V, 1), R)
		}
	}
	Z.FillBytes(x)
}

// gHash hashes X with the sub key H, and it returns a new slice.
func gHash(X []byte, H []byte) []byte {
	y := make([]byte, 16)

	for i := 0; i < len(X); i += 16 {
		Xor(y, X[i:i+16])
		mulBlock(y, H)
	}
	return y
}

// EncryptGCTR encrypts plaintext in with initial counter block ICB.
func (a *AES) EncryptGCTR(in []byte, ICB []byte) []byte {
	if in == nil {
		return in
	}

	xorBlock := make([]byte, 16*int(math.Ceil(float64(len(in))/16.0)))
	// The variable cbi(i 'th counter block) is used to preserve the state.
	cbi := make([]byte, 16)
	cbi1 := make([]byte, 16)
	copy(cbi, ICB)
	copy(cbi1, ICB)
	for i := 0; i < len(in); i += a.len {
		a.encryptBlock(cbi1, a.roundKeys)
		copy(xorBlock[i:i+a.len], cbi1)
		cbi = inc32(cbi)
		copy(cbi1, cbi)
	}

	Xor(in, xorBlock)
	return in
}

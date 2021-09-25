# AES implementation in Golang.

## Tested
|      | 128bit  | 192bit | 256bit |
| ---- | ------- | ------ | ------ |
| ECB  |   ✅    |   ✅   |   ✅  |
| CBC  |   ✅    |   ✅   |   ✅  |
| CFB  |   ✅    |   ✅   |   ✅  |
| OFB  |   ✅    |   ✅   |   ✅  |
| CTR  |   ✅    |   ✅   |   ✅  |
| GCM  |   ✅    |   ✅   |   ✅  |

All results are the same as [CyberChef](https://github.com/gchq/CyberChef)

## How To Use
Open this project in GoLand and build `main.go`.

encrypt

`encrypt -m GCM -p aes_plain1.txt -k aes_key.txt -v aes_iv.txt -c aes_cipher.txt -a aes_auth.txt --tag aes_tag.txt`

decrypt

`decrypt -m GCM -p aes_plain1.txt -k aes_key.txt -v aes_iv.txt -c aes_cipher.txt -a aes_auth.txt --tag aes_tag.txt` 

help

`encrypt help` or `decrypt help`

## Arguments
Capital or lower hex letters doesn't matter.

### key
Not being 128, 192, or 256 bits leads to an error. 

### initial vector
Shorter than 128 bits, error. 
Add a `0` to the last second position when the
length is odd. Example:`5072656E7469636548616C6C496E632` considered as `5072656E7469636548616C6C496E6302` 

Longer than 128 bit, only first 128 bits count. 

Specially, iv length can be any in GCM mode.

### plaintext length
Since padding function is used, the length does not matter. Also, add a `0` to the last second position when the 
length is odd. 

### authentication message (GCM)
Can be any length.

### tag (GCM)
Be specified as 128bit.

## Run

``` 
NAME:
   AES encryption and decryption - AES加密与解密

USAGE:
   aes_impl [global options] command [command options] [arguments...]

COMMANDS:
   encrypt  AES加密
   decrypt  AES解密
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h  show help (default: false)
> encrypt -m GCM -p aes_plain1.txt -k aes_key.txt -v aes_iv.txt -c aes_cipher.txt -a aes_auth.txt --tag aes_tag.txt
keyExpansion:
word[00]: 69616d53 74616576 96c6cc6c 696e6777 
word[01]: f7e498aa 8385fddc 154331b0 7c2d56c7 
word[02]: 2d555eba aed0a366 bb9392d6 c7bec411 
word[03]: 8749dc7c 29997f1a 920aedcc 55b429dd 
word[04]: 02ec1d80 2b75629a b97f8f56 eccba68b 
word[05]: 0dc8204e 26bd42d4 9fc2cd82 73096b09 
word[06]: 2cb721c1 0a0a6315 95c8ae97 e6c1c59e 
word[07]: 14112a4f 1e1b495a 8bd3e7cd 6d122253 
word[08]: 5d82c773 43998e29 c84a69e4 a5584bb7 
word[09]: 2c316e75 6fa8e05c a7e289b8 02bac20f 
word[10]: ee141802 81bcf85e 265e71e6 24e4b3e9 

aes_impl-128 GCM encrypted ciphertext:
block[0]: 009f9302 7c82a512 43ceff1b 56bd97c8
block[1]: 57a7122f 54eb124c d339af0c 7a00080a
block[2]: c1638c39 32b6695c 64f7cd94 6cdeb103
block[3]: d369e30e a5a75892 07db7e5a 2c4d4057
block[4]: fd

tag:
block[0]: ffdab598 c8ea91dd 78b854d0 12eebcd2

> 
```

## Thanks


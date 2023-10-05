package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"os"
	"time"
	"unsafe"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: totp secret\n")
		os.Exit(1)
	}
	secret := os.Args[1]
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "totp: %s\n", err.Error())
		os.Exit(1)
	}

	now := time.Now().Unix() / 30
	hmac := hmac.New(sha1.New, key)

	var buf [unsafe.Sizeof(now)]byte
	binary.BigEndian.PutUint64(unsafe.Slice(&buf[0], len(buf)), uint64(now))
	hmac.Write(unsafe.Slice(&buf[0], len(buf)))

	var mac []byte
	mac = hmac.Sum(mac)

	offset := mac[len(mac)-1] & 0x0F
	hash := mac[offset : offset+4]
	result := (binary.BigEndian.Uint32(hash) & 0x7FFFFFFF) % 1000000

	fmt.Println(result)
}

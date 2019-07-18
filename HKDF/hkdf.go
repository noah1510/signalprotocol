package HKDF

import (
	"errors"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

/*
Derivate derives a new key from the given secret.

It returns a key with the specified length and an error which is nil if nothing bad happened.

You need to provide a string specifying the hash function (supported:SHA512, SHA256).
You also need to provide three byte slices: the secret, the salt, the info.
They can also be nil.
*/
func Derivate(
	size int,
	hashString string,
	secret []byte,
	salt []byte,
	info []byte) ([]byte, error) {

	var returnError error
	var hashFunc func() hash.Hash

	switch hashString {
	case "SHA512":
		hashFunc = sha3.New512
	case "SHA256":
		hashFunc = sha3.New256
	default:
		returnError = errors.New("not a valid hash value " + hashString)
		return nil, returnError
	}

	hkdf := hkdf.New(hashFunc, secret, salt, info)

	key := make([]byte, size)

	if _, err := io.ReadFull(hkdf, key); err != nil {
		returnError = errors.New("error during key derivation:" + err.Error())
		return nil, returnError
	}

	return key, nil
}

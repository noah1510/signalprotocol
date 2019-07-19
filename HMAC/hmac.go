package HMAC

import (
	"crypto/hmac"
	"errors"
	"hash"

	"golang.org/x/crypto/sha3"
)

/*
HMAC returns the HMAC as a byte slice and an error which should be nil if nothing went wrong.

Just provide it with a string specifying the eused hashfunction (supported: SHA256,SHA512), the secret and the data.
*/
func HMAC(
	hashString string,
	secret []byte,
	data []byte) (result []byte, returnError error) {

	var hashFunction func() hash.Hash

	switch hashString {
	case ("SHA256"):
		hashFunction = sha3.New256
	case ("SHA512"):
		hashFunction = sha3.New512
	default:
		returnError = errors.New("Unsupproted Hash:" + hashString)
		return nil, returnError
	}

	hmac := hmac.New(hashFunction, secret)

	_, returnError = hmac.Write(data)
	if returnError != nil {
		returnError = errors.New("Error while writing data:" + returnError.Error())
		return nil, returnError
	}

	result = hmac.Sum(nil)

	return result, nil
}

package DoubleRatchet

import (
	"errors"
	"strconv"

	"github.com/noah1510/signalprotocol/HKDF"
	"github.com/noah1510/signalprotocol/X25519"
	"golang.org/x/crypto/ed25519"
)

/*
DHRatchetX25519 creates the next root key and chain key.
For the DH element X25519 is used.

You need to provide the current root key and the public and private component for the DH element.
You should also provide the length of all keys.
If the length is 0, a length of 32 will be used for all keys.

The function returns the root key, chain key and an error which is nil if everything went correctly.
*/
func DHRatchetX25519(
	rootKey []byte,
	publicKey *ed25519.PublicKey,
	privateKey *ed25519.PrivateKey,
	info []byte,
	length int) (nextRootKey []byte, nextChainKey []byte, returnError error) {

	if length%2 != 0 {
		returnError = errors.New("length should be an equal value but got " + strconv.Itoa(length))
		return nil, nil, returnError
	}

	returnError = nil

	if len(rootKey) != length {
		returnError = errors.New("expected " + strconv.Itoa(length) + " but got " + strconv.Itoa(len(rootKey)) + " as lenght of root Key")
		return nil, nil, returnError
	}

	dhElement, returnError := X25519.Exchange(privateKey, publicKey)
	if returnError != nil {
		returnError = errors.New("Error during keyexchange:" + returnError.Error())
		return nil, nil, returnError
	}

	nextRootKey, returnError = HKDF.Derivate(32, "SHA512", dhElement[:], rootKey, info)
	if returnError != nil {
		returnError = errors.New("Error during calculation of next rootKey:" + returnError.Error())
		return nil, nil, returnError
	}

	nextChainKey, returnError = HKDF.Derivate(length, "SHA512", rootKey, dhElement[:], info)
	if returnError != nil {
		returnError = errors.New("Error during calculation of next nextChainKey:" + returnError.Error())
		return nil, nil, returnError
	}

	if len(nextRootKey) != length {
		returnError = errors.New("expected " + strconv.Itoa(length) + " but got " + strconv.Itoa(len(nextRootKey)) + " as lenght of next root Key")
		return nil, nil, returnError
	}
	if len(nextChainKey) != length {
		returnError = errors.New("expected " + strconv.Itoa(length) + " but got " + strconv.Itoa(len(nextChainKey)) + " as lenght of next chain Key")
		return nil, nil, returnError
	}

	return nextRootKey, nextChainKey, nil
}

/*
MessageKey creates the next message key in a chain.

You need to provide the current chain key and the length it is supposed to have.

It returns the message key which has 2.5 times the length (e.g. if len(chainKey) = 32, len(messageKey) = 80), the next chain key and an error which is nil if nothing bad happened.

*/
func MessageKey(chainKey []byte, length int) (messageKey []byte, nextChainKey []byte, returnError error) {

	if length%2 != 0 {
		returnError = errors.New("length should be an equal value but got " + strconv.Itoa(length))
		return nil, nil, returnError
	}

	if len(chainKey) != length {
		returnError = errors.New("expected " + strconv.Itoa(length) + " but got " + strconv.Itoa(len(chainKey)) + " as lenght of chain Key")
		return nil, nil, returnError
	}

	return nil, nil, nil
}

package X3DH

import (
	"errors"
	"log"

	"github.com/noah1510/signalprotocol/HKDF"
	"github.com/noah1510/signalprotocol/X25519"

	"golang.org/x/crypto/ed25519"
)

/*
InitiatorCurve25519 performs the X3DH Keyexchange using Curve25519.
It is used by the initiator of the Keyexchange.

It returns the shared secret and an error wich is nil if nothing bad happened.

!!Make sure to check the signature of the Public Keys before using this function!!

Parameters:
	hashString: a string that specifies the used hash function (SHA256, SHA512)

	The rest is exacty what the names of the parameters are.
	The Private Keys have the type ed25519.PrivateKey and the Public Keys the type ed25519.PublicKey.
	To get those types import the package golang.org/x/crypto/ed25519.

*/
func InitiatorCurve25519(
	hashString string,
	publicIdentityKeyReceiver ed25519.PublicKey,
	publicSignedPreKeyReceiver ed25519.PublicKey,
	publicOneTimePreKeyReceiver ed25519.PublicKey,
	privateIdentityKeySender ed25519.PrivateKey,
	privateEphemeralKeySender ed25519.PrivateKey) ([]byte, error) {

	var returnError error

	//Checking if a valid hash was given
	if !(hashString == "SHA512" || hashString == "SHA256") {
		returnError = errors.New("not a valid hash value " + hashString)
		return nil, returnError
	}

	var dh1 [32]byte
	var dh2 [32]byte
	var dh3 [32]byte
	var dh4 [32]byte
	var secret []byte

	//Doing all the Keyexchanges
	// DH1 = DH(IKA, SPKB)
	dh1, returnError = X25519.Exchange(&privateIdentityKeySender, &publicSignedPreKeyReceiver)
	if returnError != nil {
		log.Printf("Error during keyexchanges!:\nDH1: %+v", dh1)
		return nil, returnError
	}

	// DH2 = DH(EKA, IKB)
	dh2, returnError = X25519.Exchange(&privateEphemeralKeySender, &publicIdentityKeyReceiver)
	if returnError != nil {
		log.Printf("Error during keyexchanges!:\nDH2: %+v", dh2)
		return nil, returnError
	}

	// DH3 = DH(EKA, SPKB)
	dh3, returnError = X25519.Exchange(&privateEphemeralKeySender, &publicSignedPreKeyReceiver)
	if returnError != nil {
		log.Printf("Error during keyexchanges!:\nDH3: %+v", dh3)
		return nil, returnError
	}

	// DH4 = DH(EKA, OPKB)
	dh4, returnError = X25519.Exchange(&privateEphemeralKeySender, &publicOneTimePreKeyReceiver)
	if returnError != nil {
		log.Printf("Error during keyexchanges!:\nDH4: %+v", dh4)
		return nil, returnError
	}

	for i := range dh1 {
		secret = append(secret, dh1[i])
	}
	for i := range dh2 {
		secret = append(secret, dh2[i])
	}
	for i := range dh3 {
		secret = append(secret, dh3[i])
	}
	for i := range dh4 {
		secret = append(secret, dh4[i])
	}

	shared, devErr := HKDF.Derivate(32, hashString, secret, nil, nil)

	if devErr != nil {
		returnError = devErr
		return nil, returnError
	}

	return shared, nil
}

/*
ReceiverCurve25519 performs the X3DH Keyexchange using Curve25519.
It is used by the receiver of the Keyexchange.

It returns the shared secret and an error wich is nil if nothing bad happened.

!!Make sure to check the signature of the Public Keys before using this function!!

Parameters:
	hashString: a string that specifies the used hash function (SHA256, SHA512)

	The rest is exacty what the names of the parameters are.
	The Private Keys have the type ed25519.PrivateKey and the Public Keys the type ed25519.PublicKey.
	To get those types import the package golang.org/x/crypto/ed25519.

*/
func ReceiverCurve25519(
	hashString string,
	privateIdentityKeyReceiver ed25519.PrivateKey,
	privateSignedPreKeyReceiver ed25519.PrivateKey,
	privateOneTimePreKeyReceiver ed25519.PrivateKey,
	publicIdentityKeySender ed25519.PublicKey,
	publicEphemeralKeySender ed25519.PublicKey) ([]byte, error) {

	var returnError error

	//Checking if a valid hash was given
	if !(hashString == "SHA512" || hashString == "SHA256") {
		returnError = errors.New("not a valid hash value " + hashString)
		return nil, returnError
	}

	var dh1 [32]byte
	var dh2 [32]byte
	var dh3 [32]byte
	var dh4 [32]byte
	var secret []byte

	//Doing all the Keyexchanges
	// DH1 = DH(IKA, SPKB)
	dh1, returnError = X25519.Exchange(&privateSignedPreKeyReceiver, &publicIdentityKeySender)
	if returnError != nil {
		log.Printf("Error during keyexchanges!:\nDH1: %+v", dh1)
		return nil, returnError
	}

	// DH2 = DH(EKA, IKB)
	dh2, returnError = X25519.Exchange(&privateIdentityKeyReceiver, &publicEphemeralKeySender)
	if returnError != nil {
		log.Printf("Error during keyexchanges!:\nDH2: %+v", dh2)
		return nil, returnError
	}

	// DH3 = DH(EKA, SPKB)
	dh3, returnError = X25519.Exchange(&privateSignedPreKeyReceiver, &publicEphemeralKeySender)
	if returnError != nil {
		log.Printf("Error during keyexchanges!:\nDH3: %+v", dh3)
		return nil, returnError
	}

	// DH4 = DH(EKA, OPKB)
	dh4, returnError = X25519.Exchange(&privateOneTimePreKeyReceiver, &publicEphemeralKeySender)
	if returnError != nil {
		log.Printf("Error during keyexchanges!:\nDH4: %+v", dh4)
		return nil, returnError
	}

	for i := range dh1 {
		secret = append(secret, dh1[i])
	}
	for i := range dh2 {
		secret = append(secret, dh2[i])
	}
	for i := range dh3 {
		secret = append(secret, dh3[i])
	}
	for i := range dh4 {
		secret = append(secret, dh4[i])
	}

	shared, devErr := HKDF.Derivate(32, hashString, secret, nil, nil)

	if devErr != nil {
		returnError = devErr
		return nil, returnError
	}

	return shared, nil
}

// TODO: Add two functions for use with x448

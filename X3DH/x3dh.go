package X3DH

import (
	"errors"
	"log"
	"signalprotocol/X25519"

	"golang.org/x/crypto/ed25519"
)

/*InitiatorCurve25519 performs the X3DH Keyexchange using Curve25519.
It is used for the initiator of the Keyexchange.

Parameters:
	hash: a string that specifies the used hash functions (SHA256, SHA512)
*/
func InitiatorCurve25519(
	hash string,
	publicIdentityKeyReceiver ed25519.PublicKey,
	publicSignedPreKeyReceiver ed25519.PublicKey,
	publicOneTimePreKeyReceiver ed25519.PublicKey,
	privateIdentityKeySender ed25519.PrivateKey,
	privateEphemeralKeySender ed25519.PrivateKey) error {

	var returnError error

	if !(hash == "SHA512" || hash == "SHA256") {
		returnError = errors.New("not a valid hash value " + hash)
		return returnError
	}

	//TODO Check Signature of Public Keys

	var dh1 [32]byte
	var dh2 [32]byte
	var dh3 [32]byte
	var dh4 [32]byte

	//Doing all the Keyexchanges
	// DH1 = DH(IKA, SPKB)
	dh1, returnError = X25519.Exchange(&privateIdentityKeySender, &publicSignedPreKeyReceiver)

	// DH2 = DH(EKA, IKB)
	dh2, returnError = X25519.Exchange(&privateEphemeralKeySender, &publicIdentityKeyReceiver)

	// DH3 = DH(EKA, SPKB)
	dh3, returnError = X25519.Exchange(&privateEphemeralKeySender, &publicSignedPreKeyReceiver)

	// DH4 = DH(EKA, OPKB)
	dh4, returnError = X25519.Exchange(&privateEphemeralKeySender, &publicOneTimePreKeyReceiver)

	if returnError != nil {
		log.Printf("Error during keyexchanges!:\nDH1: %+v\nDH2: %+v\nDH3: %+v\nDH4: %+v\n", dh1, dh2, dh3, dh4)
		return returnError
	}

	returnError = errors.New("end of function")

	return returnError
}

// TODO:Add function for receiver

// TODO: Add two functions for use with x448

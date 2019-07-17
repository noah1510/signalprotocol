package X3DH

import (
	"errors"

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

	returnError = errors.New("end of function")

	return returnError
}

// TODO:Add function for receiver

// TODO: Add two functions for use with x448

package X25519

import (
	"errors"

	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

/*Exchange does a simple x25519 keyexchange*/
func Exchange(
	privateKeyA *ed25519.PrivateKey,
	publicKeyB *ed25519.PublicKey) ([32]byte, error) {

	var returnError error
	var result [32]byte
	var priv [32]byte
	var pub [32]byte

	var privateKey [64]byte
	var publicKey [32]byte

	//Check if privateKeyA is valid then convert to [64]byte
	if len(privateKeyA.Seed()) != 32 {
		returnError = errors.New("wrong length of private key")
		return [32]byte{}, returnError
	}
	copy(privateKey[:], *privateKeyA)

	//Check if publicKeyB is valid then convert to [32]byte
	if len([]byte(*publicKeyB)) != 32 {
		returnError = errors.New("wrong length of public key")
		return [32]byte{}, returnError
	}
	copy(privateKey[:], *publicKeyB)

	//Converting the Keys to the right format
	extra25519.PrivateKeyToCurve25519(&priv, &privateKey)
	extra25519.PublicKeyToCurve25519(&pub, &publicKey)

	//Making the actual Multiplication
	curve25519.ScalarMult(&result, &priv, &pub)

	return result, returnError
}

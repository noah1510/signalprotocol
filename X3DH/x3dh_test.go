package X3DH

import (
	"log"
	"testing"

	"golang.org/x/crypto/ed25519"
)

func TestInitiatorCurve25519(t *testing.T) {
	log.Printf("starting test")

	// Creating all Keys for A

	log.Printf("Generating Keys for A")

	pubIdkA, privIdkA, errA1 := ed25519.GenerateKey(nil)
	pubPre1A, privPre1A, errA2 := ed25519.GenerateKey(nil)
	pubPre2A, privPre2A, errA3 := ed25519.GenerateKey(nil)

	if errA1 != nil || errA2 != nil || errA3 != nil {
		t.Errorf("Errors during key genreation, errA1:" + errA1.Error() + " , errA2:" + errA2.Error() + " , errA3:" + errA3.Error())
	}

	log.Printf("Public Identity Key Alice:%+v", pubIdkA)
	log.Printf("Private Identity Key Alice:%+v", privIdkA.Seed())
	log.Printf("Public Signed Pre Key Alice:%+v", pubPre1A)
	log.Printf("Private Signed Pre Key Alice:%+v", privPre1A.Seed())
	log.Printf("Public One Time Pre Key Alice:%+v", pubPre2A)
	log.Printf("Private One Time Pre Key Alice:%+v", privPre2A.Seed())

	// Creating all Keys for B
	log.Printf("Generating Keys for A")

	pubIdkB, privIdkB, errB1 := ed25519.GenerateKey(nil)
	pubPre1B, privPre1B, errB2 := ed25519.GenerateKey(nil)
	pubPre2B, privPre2B, errB3 := ed25519.GenerateKey(nil)

	if errB1 != nil || errB2 != nil || errB3 != nil {
		t.Errorf("Errors during key genreation, errB1:" + errB1.Error() + " , errB2:" + errB2.Error() + " , errB3:" + errB3.Error())
	}

	log.Printf("Public Identity Key Bob:%+v", pubIdkB)
	log.Printf("Private Identity Key Bob:%+v", privIdkB.Seed())
	log.Printf("Public Signed Pre Key Bob:%+v", pubPre1B)
	log.Printf("Private Signed Pre Key Bob:%+v", privPre1B.Seed())
	log.Printf("Public One Time Pre Key Bob:%+v", pubPre2B)
	log.Printf("Private One Time Pre Key Bob:%+v", privPre2B.Seed())

}

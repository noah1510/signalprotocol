package X25519

import (
	"log"
	"testing"

	"golang.org/x/crypto/ed25519"
)

func TestExchange(t *testing.T) {
	pub1, priv1, err1 := ed25519.GenerateKey(nil)
	pub2, priv2, err2 := ed25519.GenerateKey(nil)

	if err1 != nil || err2 != nil {
		t.Errorf("Errors during key genreation, err1:" + err1.Error() + ", err2:" + err2.Error())
	}

	log.Printf("pub1:%+v", pub1)
	log.Printf("pub2:%+v", pub2)
	log.Printf("priv1:%+v", priv1.Seed())
	log.Printf("priv2:%+v", priv2.Seed())

	res1, err3 := Exchange(&pub2, &priv1)
	res2, err4 := Exchange(&pub1, &priv2)

	if err3 != nil || err4 != nil {
		t.Errorf("Errors during key exchange, err3:" + err3.Error() + ", err4:" + err4.Error())
	}

	if res1 != res2 {
		t.Errorf("Not same result from both keyexchanges!\nresult1:%+v\nresult2:%+v", res1, res2)
	}

}

package pepper

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"golang.org/x/crypto/nacl/box"
	"io"
)

//EncryptMsg encrypt a message
func EncryptMsg(message []byte, pubKey, privKey *Key) (encrypted string, err error) {
	nonce := new([24]byte)
	if _, err = io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return
	}
	enc := box.Seal([]byte{}, message, nonce, &pubKey.Raw, &privKey.Raw)
	// full encoded message = nonce + enc
	o := append([]byte{}, nonce[:]...)
	o = append(o, enc...)
	return base64.StdEncoding.EncodeToString(o), nil
}

// DecryptMsg
func DecryptMsg(message string, pubkey, privkey *Key) (decrypted []byte, err error) {
	if len(message) < 24 {
		return decrypted, errors.New("Bad encrypted message")
	}

	msg, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return
	}

	// read nonce
	var nonce [24]byte
	for i := 0; i < 24; i++ {
		nonce[i] = msg[i]
	}

	// read encrypted message
	var ok bool
	encrypted := msg[24:]
	decrypted, ok = box.Open([]byte{}, encrypted, &nonce, &pubkey.Raw, &privkey.Raw)
	if !ok {
		return decrypted, errors.New("hu something wrong with your encrypted msg, i'm unable to decrypt it")
	}
	return decrypted, nil

}

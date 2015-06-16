package pepper

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"path"

	"golang.org/x/crypto/nacl/box"
)

// newNonce generate a new nonce
// collision: 1/255^24
func newNonce() (*[24]byte, error) {
	var nonce [24]byte
	_, err := io.ReadFull(rand.Reader, nonce[:])
	return &nonce, err
}

// Encrypt return encrypted data
func Encrypt(data *[]byte, pubKey, privKey *Key) ([]byte, error) {
	nonce, err := newNonce()
	if err != nil {
		return []byte{}, err
	}
	out := make([]byte, 24)
	copy(out, nonce[:])
	out = box.Seal(out, *data, nonce, &pubKey.Raw, &privKey.Raw)
	return out, nil
}

func Decrypt(data *[]byte, pubKey, privKey *Key) ([]byte, error) {
	if len(*data) < 24 {
		return []byte{}, errors.New("Bad encrypted data")
	}
	d := *data
	var nonce [24]byte
	copy(nonce[:], d[:24])
	out, ok := box.Open(nil, d[24:], &nonce, &pubKey.Raw, &privKey.Raw)
	if !ok {
		return []byte{}, errors.New("hu something wrong with your encrypted data, i'm unable to decrypt it")
	}
	return out, nil

}

//EncryptMsg encrypt a message
func EncryptMsg(message []byte, pubKey, privKey *Key) (string, error) {
	out, err := Encrypt(&message, pubKey, privKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(out), nil
}

// DecryptMsg
func DecryptMsg(message string, pubKey, privKey *Key) ([]byte, error) {
	msg, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return []byte{}, err
	}
	out, err := Decrypt(&msg, pubKey, privKey)
	if err != nil {
		return []byte{}, err
	}
	return out, nil
}

// encDecFile ecrypt or decrytp file
// encrypt == true -> encrypt
// encrypt != true -> decrypt
func encDecFile(encrypt bool, in, out string, pubKey, privKey *Key) error {
	if _, err := os.Stat(in); os.IsNotExist(err) {
		return errors.New("no such file " + in)
	}
	outdir := path.Dir(out)
	if _, err := os.Stat(outdir); os.IsNotExist(err) {
		return errors.New("no such directory: " + outdir)
	}
	inb, err := ioutil.ReadFile(in)
	if err != nil {
		return err
	}
	var outb []byte
	if encrypt {
		outb, err = Encrypt(&inb, pubKey, privKey)
	} else {
		outb, err = Decrypt(&inb, pubKey, privKey)
	}
	if err != nil {
		return err
	}
	return ioutil.WriteFile(out, outb, 0600)

}

// EncryptFile encrypt in to out
func EncryptFile(in, out string, pubKey, privKey *Key) error {
	return encDecFile(true, in, out, pubKey, privKey)
}

func DecryptFile(in, out string, pubKey, privKey *Key) error {
	return encDecFile(false, in, out, pubKey, privKey)
}

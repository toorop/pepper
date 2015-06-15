// nacl wrappers
// the idea behind those wrappers is to use pepper package/API without taking care of nacl pkg.

package pepper

import (
	"io"

	"golang.org/x/crypto/nacl/box"
)

// GenerateKey generates a new public/private key pair suitable for use with Seal and Open.
func GenerateKey(rand io.Reader) (publicKey, privateKey *[32]byte, err error) {
	return box.GenerateKey(rand)
}

// BoxSeal appends an encrypted and authenticated copy of message to out, which will be Overhead
// bytes longer than the original and must not overlap. The nonce must be unique for each
// distinct message for a given pair of keys.
func BoxSeal(out, message []byte, nonce *[24]byte, peersPublicKey, privateKey *[32]byte) []byte {
	return box.Seal(out, message, nonce, peersPublicKey, privateKey)
}

// BoxOpen authenticates and decrypts a box produced by Seal and appends the
// message to out, which must not overlap box. The output will be Overhead
// bytes smaller than box.
func BoxOpen(out, b []byte, nonce *[24]byte, peersPublicKey, privateKey *[32]byte) ([]byte, bool) {
	return box.Open(out, b, nonce, peersPublicKey, privateKey)
}

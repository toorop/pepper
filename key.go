package pepper

import (
	"encoding/base64"
)

type Key struct {
	Raw [32]byte
}

// KeyFromString return key struct from string
func KeyFromString(kstr string) (*Key, error) {
	//r:=[32]byte{}
	kb, err := base64.StdEncoding.DecodeString(kstr)
	if err != nil {
		panic(err)
	}
	k := &Key{}
	for i, b := range kb {
		k.Raw[i] = b
	}
	return k, nil
}

func (k *Key) String() string {
	if k.Raw == [32]byte{} {
		return ""
	}
	t := []byte{}
	for _, b := range k.Raw {
		t = append(t, b)
	}
	return base64.StdEncoding.EncodeToString(t)
}

package pepper

import (
	"encoding/base64"
	"io/ioutil"
	"os"
	"os/user"
	"path"
)

// Key represent a key
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

// String return key as base64 encoded string
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

// SaveKeysInHomeDir save keys from current user home dir
func SaveKeysInHomeDir(pub, priv *[32]byte) error {
	u, err := user.Current()
	if err != nil {
		return err
	}
	// pepper dir exists ?
	pepperDir := path.Join(u.HomeDir, ".pepper")
	if _, err := os.Stat(pepperDir); os.IsNotExist(err) {
		if err = os.Mkdir(pepperDir, 0700); err != nil {
			return err
		}
	}
	// save pub key
	p := *pub
	if err = ioutil.WriteFile(path.Join(pepperDir, "key.pub"), p[:], 0600); err != nil {
		return err
	}

	// save pivate key
	p = *priv
	if err = ioutil.WriteFile(path.Join(pepperDir, "key.priv"), p[:], 0600); err != nil {
		return err
	}
	return nil
}

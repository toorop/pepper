package pepper

import (
	"encoding/base64"
	"errors"
	"io/ioutil"
	"os"
	"path"
)

// Key represent a key
type Key struct {
	Raw  [32]byte
	Type string
}

// KeyFromString return key struct from string
func KeyFromString(kstr string) (*Key, error) {
	//r:=[32]byte{}
	kb, err := base64.StdEncoding.DecodeString(kstr)
	if err != nil {
		panic(err)
	}
	k := &Key{}
	// check key lenght
	if len(kb) != 32 {
		return nil, errors.New("Bad key: " + kstr)
	}
	copy(k.Raw[:], kb)
	return k, nil
}

// GetUserKeyFromHomeDir returns public or private key of current user loade from his home dir
func KeyFromHomeDir(puborpriv string) (key *Key, err error) {
	if puborpriv != "private" && puborpriv != "public" {
		return nil, errors.New("GetUserKeyFromHome params must be 'private' or 'public'. " + puborpriv + " given.")
	}
	// user.Current not implemented on OSX
	//u, err := user.Current()
	/*u, err := user.LookupId(strconv.FormatInt(int64(os.Getuid()), 10))
	if err != nil {
		return nil, err
	}
	println(u.HomeDir)
	os.Exit(0)*/
	homeDir, err := GetHomeDir()
	if err != nil {
		return nil, err
	}

	// load public key
	k, err := ioutil.ReadFile(path.Join(homeDir, ".pepper", "key."+puborpriv))
	if err != nil {
		return nil, err
	}

	raw := [32]byte{}
	for i := 0; i < 32; i++ {
		raw[i] = k[i]
	}
	return &Key{Raw: raw}, nil
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

// SaveInHomeDir save key in home dir
func (k *Key) SaveInHomeDir() error {
	/*u, err := user.Current()
	if err != nil {
		return err
	}*/
	homeDir, err := GetHomeDir()
	if err != nil {
		return err
	}

	// pepper dir exists ?
	pepperDir := path.Join(homeDir, ".pepper")
	if _, err := os.Stat(pepperDir); os.IsNotExist(err) {
		if err = os.Mkdir(pepperDir, 0700); err != nil {
			return err
		}
	}
	return ioutil.WriteFile(path.Join(pepperDir, "key."+k.Type), k.Raw[:], 0600)
}

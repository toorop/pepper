package main

import (
	//"bufio"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/codegangsta/cli"
)

type key struct {
	raw [32]byte
}

func handelErr(err error) {
	if err != nil {
		dieError(err.Error())
	}
}

func dieError(msg string) {
	println(msg)
	os.Exit(1)
}

func (k *key) String() string {
	if k.raw == [32]byte{} {
		return ""
	}
	t := []byte{}
	for _, b := range k.raw {
		t = append(t, b)
	}
	return base64.StdEncoding.EncodeToString(t)
}

func getKeys(c *cli.Context) (privkey, pubkey *key, err error) {
	privkeyStr := c.String("privkey")
	if privkeyStr == "" {
		privkeyStr = os.Getenv("PEPPER_PRIVATE_KEY")
	}
	if privkeyStr == "" {
		return nil, nil, errors.New("No private key found")
	}
	privkey, err = newKeyFromString(privkeyStr)

	// pubkey
	pubkeyStr := c.String("pubkey")
	if pubkeyStr == "" {
		pubkeyStr = os.Getenv("PEPPER_PUBLIC_KEY")
	}
	if pubkeyStr == "" {
		return nil, nil, errors.New("No public key found")
	}
	pubkey, err = newKeyFromString(pubkeyStr)
	return
}

// newKeyFromString return key struct from string
func newKeyFromString(kstr string) (*key, error) {
	//r:=[32]byte{}
	kb, err := base64.StdEncoding.DecodeString(kstr)
	if err != nil {
		panic(err)
	}
	k := &key{}
	for i, b := range kb {
		k.raw[i] = b
	}
	return k, nil
}

// generateKey generate a new set of key
var generateKey = cli.Command{
	Name:  "genkey",
	Usage: "Create new set of keys",
	Action: func(c *cli.Context) {
		pub, priv, err := box.GenerateKey(rand.Reader)
		handelErr(err)

		pubKey := &key{
			raw: *pub,
		}

		privKey := &key{
			raw: *priv,
		}

		os.Clearenv()
		os.Setenv("PEPPER_PRIVATE_KEY", privKey.String())
		os.Setenv("PEPPER_PUBLIC_KEY", pubKey.String())

		fmt.Printf("Private key: %s\n", privKey)
		fmt.Printf("Public key: %s\n", pubKey)

	},
}

// encmsg encrypt a message
var encmsg = cli.Command{
	Name:  "encmsg",
	Usage: "Encrypt à text message",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:   "privkey, r",
			Value:  "",
			Usage:  "Your private key",
			EnvVar: "PEPPER_PRIVATE_KEY",
		}, cli.StringFlag{
			Name:  "pubkey, u",
			Value: "",
			Usage: "Peer public key",
		},
	},
	Action: func(c *cli.Context) {
		var err error
		// message to be encrypted
		msg := []byte(c.Args().First())
		if len(msg) == 0 {
			// try stdin
			// timeout on read
			// if nothing to raise.
			c := make(chan byte, 1)
			go func() {
				b := make([]byte, 1)
				_, err := os.Stdin.Read(b)
				handelErr(err)
				c <- b[0]
			}()
			select {
			case b := <-c:
				msg, err = ioutil.ReadAll(os.Stdin)
				handelErr(err)
				msg = append([]byte{b}, msg...)
			case <-time.After(time.Millisecond * 10):
				// black hole
			}

		}
		if len(msg) == 0 {
			println("Nothing to encrypt\n pepper encmsg " + `"message to encrypt"` + "\nor\n echo " + `"message to encrypt"` + " | pepper encmsg" + "\nor\n cat file.txt | pepper encmsg")
			os.Exit(1)
		}

		// get keys
		privkey, pubkey, err := getKeys(c)
		handelErr(err)

		//println(pubkey.String())

		// New nonce
		nonce := new([24]byte)
		_, err = io.ReadFull(rand.Reader, nonce[:])
		handelErr(err)
		out := []byte{}
		out = box.Seal(out, msg, nonce, &pubkey.raw, &privkey.raw)
		n := []byte{}
		for _, b := range *nonce {
			n = append(n, b)
		}

		fmt.Printf("Nonce: %s\nEncrypted:\n%s\n", base64.StdEncoding.EncodeToString(n), base64.StdEncoding.EncodeToString(out))

	},
}

// decmsg decrypt a message
var decmsg = cli.Command{
	Name:  "decmsg",
	Usage: "Decrypt à text message",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:   "privkey, r",
			Value:  "",
			Usage:  "Your private key",
			EnvVar: "PEPPER_PRIVATE_KEY",
		}, cli.StringFlag{
			Name:  "pubkey, u",
			Value: "",
			Usage: "Peer public key",
		}, cli.StringFlag{
			Name:  "nonce, n",
			Value: "",
			Usage: "Nonce",
		},
	},
	Action: func(c *cli.Context) {
		if len(c.Args()) != 1 {
			panic(errors.New("no message to decrypt"))
		}

		// encrypted message
		encrypted, err := base64.StdEncoding.DecodeString(c.Args().First())
		handelErr(err)

		// get keys
		privkey, pubkey, err := getKeys(c)
		handelErr(err)

		//println(pubkey.String())

		// nonce
		nonceStr := c.String("nonce")
		if nonceStr == "" {
			panic(errors.New("No nonce specified"))
		}
		nonceb, err := base64.StdEncoding.DecodeString(nonceStr)
		handelErr(err)
		nonce := new([24]byte)
		for i, b := range nonceb {
			nonce[i] = b
		}
		out := []byte{}
		r, _ := box.Open(out, encrypted, nonce, &pubkey.raw, &privkey.raw)
		fmt.Printf("%s\n", string(r))
	},
}

// encfile encrypt a file
var encfile = cli.Command{
	Name:  "encfile",
	Usage: "Encrypt a file",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:   "privkey, r",
			Value:  "",
			Usage:  "Your private key",
			EnvVar: "PEPPER_PRIVATE_KEY",
		}, cli.StringFlag{
			Name:  "pubkey, u",
			Value: "",
			Usage: "Peer public key",
		}, cli.StringFlag{
			Name:  "in, i",
			Value: "",
			Usage: "File to encrypt",
		}, cli.StringFlag{
			Name:  "out, o",
			Value: "",
			Usage: "Path for encrypted file",
		},
	},
	Action: func(c *cli.Context) {
		var err error
		// file to be encrypted
		in := c.String("in")
		if in == "" {
			dieError("You must provide a file to encrytp\npepper encfile -i FILE_TO_ENCRYPT [-o OUTPUT_FILE]")
		}
		if _, err = os.Stat(in); os.IsNotExist(err) {
			dieError("no such file or directory: " + in)
		}

		// output
		out := c.String("out")
		if out == "" {
			out = in + ".enc"
		}
		outdir := path.Dir(out)
		if _, err = os.Stat(outdir); os.IsNotExist(err) {
			dieError("no such file or directory: " + outdir)
		}

		// get keys
		privkey, pubkey, err := getKeys(c)
		handelErr(err)

		// New nonce
		nonce := new([24]byte)
		_, err = io.ReadFull(rand.Reader, nonce[:])
		handelErr(err)

		outb := []byte{}
		inb, err := ioutil.ReadFile(in)
		handelErr(err)

		outb = box.Seal(outb, inb, nonce, &pubkey.raw, &privkey.raw)
		handelErr(ioutil.WriteFile(out, outb, 0644))

		n := []byte{}
		for _, b := range *nonce {
			n = append(n, b)
		}

		fmt.Printf("Nonce: %s\n", base64.StdEncoding.EncodeToString(n))
	},
}

// encfile encrypt a file
var decfile = cli.Command{
	Name:  "decfile",
	Usage: "Decrypt a file",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:   "privkey, r",
			Value:  "",
			Usage:  "Your private key",
			EnvVar: "PEPPER_PRIVATE_KEY",
		}, cli.StringFlag{
			Name:  "pubkey, u",
			Value: "",
			Usage: "Peer public key",
		}, cli.StringFlag{
			Name:  "in, i",
			Value: "",
			Usage: "File to decrypt",
		}, cli.StringFlag{
			Name:  "out, o",
			Value: "",
			Usage: "Path for decrypted file",
		}, cli.StringFlag{
			Name:  "nonce, n",
			Value: "",
			Usage: "Nonce",
		},
	},
	Action: func(c *cli.Context) {
		var err error

		nonceStr := c.String("nonce")
		if nonceStr == "" {
			dieError("You must provide a nonce\npepper decfile -i FILE_TO_ENCRYPT -n NONCE [-o OUTPUT_FILE]")
		}
		nonceb, err := base64.StdEncoding.DecodeString(nonceStr)
		handelErr(err)
		nonce := new([24]byte)
		for i, b := range nonceb {
			nonce[i] = b
		}

		in := c.String("in")
		if in == "" {
			dieError("You must provide a file to decrypt\npepper decfile -i FILE_TO_ENCRYPT -n NONCE [-o OUTPUT_FILE]")
		}
		if _, err = os.Stat(in); os.IsNotExist(err) {
			dieError("no such file or directory: " + in)
		}

		// output
		out := c.String("out")
		if out == "" {
			out = in + ".decrypted"
		}
		outdir := path.Dir(out)
		if _, err = os.Stat(outdir); os.IsNotExist(err) {
			dieError("no such file or directory: " + outdir)
		}

		// get keys
		privkey, pubkey, err := getKeys(c)
		handelErr(err)

		inb, err := ioutil.ReadFile(in)
		handelErr(err)

		outb := []byte{}
		outb, _ = box.Open(outb, inb, nonce, &pubkey.raw, &privkey.raw)
		handelErr(ioutil.WriteFile(out, outb, 0644))

		println("Decrypted file saved as: " + out)
	},
}

// sendMsg TODO
var sendmsg = cli.Command{
	Name:  "sendmsg",
	Usage: "Send message (or file, or ...) to public key address",
	Action: func(c *cli.Context) {
	},
}

// getMsg TODO
var getmsg = cli.Command{
	Name:  "getmsg",
	Usage: "Retrieve & decode message (or file, or ...)",
	Action: func(c *cli.Context) {
	},
}

func main() {
	app := cli.NewApp()
	app.Name = "pepper"
	app.Usage = "repellent for black boxes"
	app.Author = "Stéphane Depierrepont aka toorop"
	app.Email = "toorop@toorop.fr"
	app.Version = "0.0.6"
	app.Commands = []cli.Command{
		generateKey,
		encmsg,
		decmsg,
		encfile,
		decfile,
		sendmsg,
		getmsg,
	}
	app.Action = func(c *cli.Context) {
		println("go")
	}

	app.Run(os.Args)
}

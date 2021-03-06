package main

import (
	//"bufio"
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"time"

	"github.com/codegangsta/cli"

	"github.com/toorop/pepper"
)

func handleErr(err error) {
	if err != nil {
		dieError(err.Error())
	}
}

func dieError(msg string) {
	fmt.Println(msg)
	os.Exit(1)
}

// getKeys returns keys used for enc/dec from:
// - cmd line option
// - environment vars
// - ~/.pepper/private.key /.pepper/public.key
func getKeys(c *cli.Context) (privkey, pubkey *pepper.Key, err error) {
	privkeyStr := c.String("privkey")
	if privkeyStr == "" {
		privkeyStr = os.Getenv("PEPPER_PRIVATE_KEY")
	}
	if privkeyStr != "" {
		privkey, err = pepper.KeyFromString(privkeyStr)
		handleErr(err)
	} else {
		// From homedir
		privkey, err = pepper.KeyFromHomeDir("private")
		handleErr(err)
	}
	if privkey == nil {
		return nil, nil, errors.New("No private key found")
	}

	// pubkey
	pubkeyStr := c.String("pubkey")
	if pubkeyStr == "" {
		pubkeyStr = os.Getenv("PEPPER_PUBLIC_KEY")
	}
	if pubkeyStr != "" {
		pubkey, err = pepper.KeyFromString(pubkeyStr)
		handleErr(err)
	} else {
		// From homedir
		pubkey, err = pepper.KeyFromHomeDir("public")
		handleErr(err)
	}
	return
}

// getInput return input in the order below
// - from command line
// - from stdin
func getInput(c *cli.Context) (*[]byte, error) {
	var err error
	input := []byte(c.Args().First())
	if len(input) == 0 {
		// try stdin
		// timeout on read
		// if nothing to raise.
		c := make(chan byte, 1)
		go func() {
			b := make([]byte, 1)
			_, err := os.Stdin.Read(b)
			handleErr(err)
			c <- b[0]
		}()
		select {
		case b := <-c:
			input, err = ioutil.ReadAll(os.Stdin)
			if err != nil {
				return nil, err
			}
			input = append([]byte{b}, input...)
		case <-time.After(time.Millisecond * 10):
			println("timeout")
			// some kind of magic happens here
		}
	}
	return &input, nil
}

// generateKey generates a new set of key
var generateKey = cli.Command{
	Name:  "genkey",
	Usage: "Create new set of keys",
	Action: func(c *cli.Context) {
		pub, priv, err := pepper.GenerateKey(rand.Reader)
		handleErr(err)

		// save in ~/.pepper/key.priv|pub ?
		homeDir, err := pepper.GetHomeDir()
		handleErr(err)

		handleErr(err)
		var r []byte

		pubKey := &pepper.Key{
			Raw:  *pub,
			Type: "public",
		}

		privKey := &pepper.Key{
			Raw:  *priv,
			Type: "private",
		}

		fmt.Printf("Private key: %s\n", privKey)
		fmt.Printf("Public key: %s\n", pubKey)

		for {
			fmt.Printf("Would you like to save keys as your keys in %s ?\nWarning if keys exists they will be replaced (y/n) :", path.Join(homeDir, ".pepper"))
			r, _, _ = bufio.NewReader(os.Stdin).ReadLine()
			if r[0] == 110 || r[0] == 121 {
				break
			}
		}
		if r[0] == 121 {
			handleErr(pubKey.SaveInHomeDir())
			handleErr(privKey.SaveInHomeDir())
		}
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
		msg, err := getInput(c)
		handleErr(err)
		if len(*msg) == 0 {
			println("Nothing to encrypt\n pepper encmsg " + `"message to encrypt"` + "\nor\n echo " + `"message to encrypt"` + " | pepper encmsg" + "\nor\n cat file.txt | pepper encmsg")
			os.Exit(1)
		}
		// get keys
		privKey, pubKey, err := getKeys(c)
		handleErr(err)

		encrypted, err := pepper.EncryptMsg(*msg, pubKey, privKey)
		handleErr(err)

		println(encrypted)

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
		},
	},
	Action: func(c *cli.Context) {
		msg, err := getInput(c)
		handleErr(err)
		if len(*msg) == 0 {
			println("Nothing to decrypt\n pepper decmsg " + `"message to encrypt"` + "\nor\n echo " + `"message to decrypt"` + " | pepper decmsg" + "\nor\n cat file.txt | pepper decmsg")
			os.Exit(1)
		}

		// get keys
		privKey, pubKey, err := getKeys(c)
		handleErr(err)

		decrypted, err := pepper.DecryptMsg(string(*msg), pubKey, privKey)
		println(string(decrypted))
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
			Usage: "Full path for encrypted file",
		},
	},
	Action: func(c *cli.Context) {
		var err error
		// input
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
		privKey, pubKey, err := getKeys(c)
		handleErr(err)

		handleErr(pepper.EncryptFile(in, out, pubKey, privKey))
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
			Usage: "Full path for decrypted file",
		},
	},
	Action: func(c *cli.Context) {
		// in
		in := c.String("in")
		if in == "" {
			dieError("You must provide a file to decrypt\npepper decfile -i FILE_TO_ENCRYPT -n NONCE [-o OUTPUT_FILE]")
		}

		// out
		out := c.String("out")
		if out == "" {
			out = in + ".decrypted"
		}

		// get keys
		privKey, pubKey, err := getKeys(c)
		handleErr(err)
		handleErr(pepper.DecryptFile(in, out, pubKey, privKey))
	},
}

// Print user keys as string
var dumpkeys = cli.Command{
	Name:  "dumpkeys",
	Usage: "Print user keys as string",
	Action: func(c *cli.Context) {
		pubKey, err := pepper.KeyFromHomeDir("public")
		handleErr(err)
		privKey, err := pepper.KeyFromHomeDir("private")
		handleErr(err)
		fmt.Printf("Public key:%s\nPrivate key:%s\n", pubKey, privKey)
	},
}

// Save keys in user HOMEDIR/.pepper
var savekeys = cli.Command{
	Name:  "savekeys",
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
		},
	},
	Action: func(c *cli.Context) {
		// public key
		pubstr := c.String("u")
		if pubstr == "" {
			dieError("public key is missing \npepper savekeys -u PUBLIC_KEY -r PRIVATE_KEY")
		}

		// private key
		privstr := c.String("r")
		if privstr == "" {
			dieError("private key is missing \npepper savekeys -u PUBLIC_KEY -r PRIVATE_KEY")
		}

		pubKey, err := pepper.KeyFromString(pubstr)
		handleErr(err)
		pubKey.Type = "public"
		privKey, err := pepper.KeyFromString(privstr)
		handleErr(err)
		privKey.Type = "private"
		handleErr(pubKey.SaveInHomeDir())
		handleErr(privKey.SaveInHomeDir())
	},
}

func main() {
	app := cli.NewApp()
	app.Name = "pepper"
	app.Usage = "repellent for black boxes"
	app.Author = "Stéphane Depierrepont aka toorop"
	app.Email = "toorop@toorop.fr"
	app.Version = "0.0.1"
	app.Commands = []cli.Command{
		generateKey,
		encmsg,
		decmsg,
		encfile,
		decfile,
		dumpkeys,
		savekeys,
	}
	app.Run(os.Args)
}

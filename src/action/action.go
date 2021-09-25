package action

import (
	"context"
	"errors"
	"flag"
	"github.com/CrackedPoly/AES-implementation-in-Golang/src/aes"
	"github.com/CrackedPoly/AES-implementation-in-Golang/src/utils"
	"github.com/otokaze/go-kit/log"
	"github.com/peterh/liner"
	"github.com/urfave/cli/v2"
	"strings"
)

func EncryptAction(ctx *cli.Context) (err error) {
	mode := ctx.String("m")
	plainfile := ctx.String("p")
	keyfile := ctx.String("k")
	vifile := ctx.String("v")
	cipherfile := ctx.String("c")
	authfile := ctx.String("a")
	tagfile := ctx.String("tag")

	plain := utils.ReadBytesHex(plainfile)
	key := utils.ReadBytesHex(keyfile)
	iv := utils.ReadBytesHex(vifile)
	auth := utils.ReadBytesHex(authfile)

	_aes, err := aes.NewAES(key)
	if err != nil {
		log.Error("%s", err)
		return err
	}
	var ciphertext []byte

	switch strings.ToTitle(mode) {
	case "ECB":
		ciphertext = _aes.EncryptECB(plain, utils.PKCS7Padding)
	case "CBC":
		ciphertext = _aes.EncryptCBC(plain, iv[0:16], utils.PKCS7Padding)
	case "CFB":
		ciphertext = _aes.EncryptCFB(plain, iv[0:16], 16)
	case "OFB":
		ciphertext = _aes.EncryptOFB(plain, iv[0:16])
	case "CTR":
		ciphertext = _aes.EncryptCTR(plain, iv[0:16])
	case "GCM":
		var tag []byte
		ciphertext, tag = _aes.EncryptGCM(plain, iv, auth, 16)
		utils.WriteBytesHex(tagfile, tag)
	default:
		log.Error("invalid mode")
		return errors.New("invalid mode")
	}
	utils.WriteBytesHex(cipherfile, ciphertext)
	return nil
}

func DecryptAction(ctx *cli.Context) (err error) {
	mode := ctx.String("m")
	plainfile := ctx.String("p")
	keyfile := ctx.String("k")
	vifile := ctx.String("v")
	cipherfile := ctx.String("c")
	authfile := ctx.String("a")
	tagfile := ctx.String("tag")

	ciphertext := utils.ReadBytesHex(cipherfile)
	key := utils.ReadBytesHex(keyfile)
	iv := utils.ReadBytesHex(vifile)
	auth := utils.ReadBytesHex(authfile)
	tag := utils.ReadBytesHex(tagfile)

	_aes, err := aes.NewAES(key)
	if err != nil {
		log.Error("%s", err)
		return err
	}

	var plaintext []byte
	switch strings.ToTitle(mode) {
	case "ECB":
		plaintext = _aes.DecryptECB(ciphertext, utils.PKCS7Unpadding)
	case "CBC":
		plaintext = _aes.DecryptCBC(ciphertext, iv[0:16], utils.PKCS7Unpadding)
	case "CFB":
		plaintext = _aes.DecryptCFB(ciphertext, iv[0:16], 16)
	case "OFB":
		plaintext = _aes.DecryptOFB(ciphertext, iv[0:16])
	case "CTR":
		plaintext = _aes.EncryptCTR(ciphertext, iv[0:16])
	case "GCM":
		plaintext = _aes.DecryptGCM(ciphertext, iv, auth, tag)
	default:
		log.Error("invalid mode")
		return errors.New("invalid mode")
	}
	utils.WriteBytesHex(plainfile, plaintext)
	return nil
}

func AfterAction(ctx *cli.Context) (err error) {
	line := liner.NewLiner()
	line.SetCtrlCAborts(true)
	defer line.Close()
	line.SetCompleter(func(line string) (cs []string) {
		for _, c := range ctx.App.Commands {
			if strings.HasPrefix(c.Name, strings.ToLower(line)) {
				cs = append(cs, c.Name)
			}
		}
		return
	})
	for {
		var input string
		if input, err = line.Prompt("> "); err != nil {
			if err == liner.ErrPromptAborted {
				err = nil
				return
			}
			log.Error("line.Prompt() error(%v)", err)
			continue
		}
		line.AppendHistory(input)
		input = strings.TrimSpace(input)
		args := strings.Split(input, " ")
		if args[0] == "" {
			continue
		}
		var command *cli.Command
		if command = ctx.App.Command(args[0]); command == nil {
			log.Error("command(%s) not found!", args[0])
			continue
		}
		var fset = flag.NewFlagSet(args[0], flag.ContinueOnError)
		for _, f := range command.Flags {
			f.Apply(fset)
		}
		if !command.SkipFlagParsing {
			if err = fset.Parse(args[1:]); err != nil {
				if err == flag.ErrHelp {
					err = nil
					continue
				}
				log.Error("fs.Parse(%v) error(%v)", args[1:], err)
				continue
			}
		}
		var key interface{} = "args"
		nCtx := cli.NewContext(ctx.App, fset, ctx)
		nCtx.Context = context.WithValue(nCtx.Context, key, args[1:])
		nCtx.Command = command
		command.Action(nCtx)
	}
}

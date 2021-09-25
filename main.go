package main

import (
	"github.com/CrackedPoly/AES-implementation-in-Golang/src/action"
	"github.com/urfave/cli/v2"
	"log"
	"os"
	"sort"
)

func main() {
	var app = &cli.App{
		Name:                 "AES encryption and decryption",
		Usage:                "AES加密与解密",
		EnableBashCompletion: true,
		Commands: cli.Commands{
			{
				Name:   "encrypt",
				Usage:  "AES加密",
				Action: action.EncryptAction,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "mode",
						Usage:    "指定加密的操作模式，有ECB、CBC、CFB、OFB、CTR、GCM六种",
						Aliases:  []string{"m"},
						Required: true,
					},
					&cli.StringFlag{
						Name:     "plainfile",
						Usage:    "指定明文件的位置和名称",
						Aliases:  []string{"p"},
						Required: true,
					},
					&cli.StringFlag{
						Name:     "keyfile",
						Usage:    "指定密钥文件的位置和名称",
						Aliases:  []string{"k"},
						Required: true,
					},
					&cli.StringFlag{
						Name:    "vifile",
						Usage:   "指定初始化向量文件的位置和名称",
						Aliases: []string{"v"},
					},
					&cli.StringFlag{
						Name:     "cipherfile",
						Usage:    "指定密文文件的位置和名称",
						Aliases:  []string{"c"},
						Required: true,
					},
					&cli.StringFlag{
						Name:     "authfile",
						Usage:    "指定GCM模式中鉴别信息文件的位置和名称",
						Aliases:  []string{"a"},
						Required: true,
					},
					&cli.StringFlag{
						Name:     "tagfile",
						Usage:    "指定标志文件的位置和名称",
						Aliases:  []string{"tag"},
						Required: true,
					},
				},
			},
			{
				Name:   "decrypt",
				Usage:  "AES解密",
				Action: action.DecryptAction,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "mode",
						Usage:    "指定解密的操作模式，有ECB、CBC、CFB、OFB、CTR、GCM六种",
						Aliases:  []string{"m"},
						Required: true,
					},
					&cli.StringFlag{
						Name:     "plainfile",
						Usage:    "指定明文件的位置和名称",
						Aliases:  []string{"p"},
						Required: true,
					},
					&cli.StringFlag{
						Name:     "keyfile",
						Usage:    "指定密钥文件的位置和名称",
						Aliases:  []string{"k"},
						Required: true,
					},
					&cli.StringFlag{
						Name:     "vifile",
						Usage:    "指定初始化向量文件的位置和名称",
						Aliases:  []string{"v"},
						Required: true,
					},
					&cli.StringFlag{
						Name:     "cipherfile",
						Usage:    "指定密文文件的位置和名称",
						Aliases:  []string{"c"},
						Required: true,
					},
					&cli.StringFlag{
						Name:     "authfile",
						Usage:    "指定GCM模式中鉴别信息文件的位置和名称",
						Aliases:  []string{"a"},
						Required: true,
					},
					&cli.StringFlag{
						Name:     "tagfile",
						Usage:    "指定标志文件的位置和名称",
						Aliases:  []string{"tag"},
						Required: true,
					},
				},
			},
		},
		Action: func(ctx *cli.Context) (err error) {
			_ = ctx.App.Command("help").Action(ctx)
			_ = action.AfterAction(ctx)
			return
		},
	}

	sort.Sort(cli.FlagsByName(app.Flags))
	err := app.Run(os.Args)
	if err != nil {
		log.Fatalln(err)
	}

}

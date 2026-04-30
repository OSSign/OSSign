package main

import (
	"bytes"
	"context"

	"github.com/sassoftware/relic/v8/lib/certloader"
	rvfs "github.com/sassoftware/relic/v8/lib/vfs"
)

var filetypeMapper = map[string]func(input *rvfs.File, signerCert *certloader.Certificate, filename string, outfile *rvfs.File, ctx context.Context) error{
	"msi":         SignMsi,
	"exe":         SignPecoff,
	"dll":         SignPecoff,
	"ps1":         SignPowershell,
	"psd1":        SignPowershell,
	"psm1":        SignPowershell,
	"appx":        SignAppx,
	"appmanifest": SignAppmanifest,
	"dmg":         SignDmg,
	"machos":      SignMachos,
}

func SignAuto(input *rvfs.File, signerCert *certloader.Certificate, filename string, outfile *rvfs.File, ctx context.Context) error {
	fileExt := input.Name()
	if dotIndex := bytes.LastIndexByte([]byte(fileExt), '.'); dotIndex != -1 {
		fileExt = fileExt[dotIndex+1:]
	}

	if signFunc, ok := filetypeMapper[fileExt]; ok {
		return signFunc(input, signerCert, filename, outfile, ctx)
	}

	// Return default (pecoff)
	return SignPecoff(input, signerCert, filename, outfile, ctx)
}

package main

import (
	"github.com/cloudflare/cfrpki/validator/pki"
	"io/ioutil"
	"os"
	"path/filepath"
)

func main() {
	smManager := pki.NewTestManagerWithSM()
	roa, _ := pki.SignROAWithSM(smManager)
	pki.AddROAToManifestWithSM(smManager, roa)

	for k,v :=range smManager.FSManager.Files{
		fileName:= filepath.Base(k)
		err := ioutil.WriteFile("./tmp/"+fileName, v, os.ModePerm)
		if err != nil{
			panic(err)
		}
	}

}

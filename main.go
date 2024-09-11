package main

import (
	_ "embed"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const doc = `
Create Client Secret for Apple API

https://developer.apple.com/documentation/accountorganizationaldatasharing/creating-a-client-secret
`

func main() {
	var (
		outFileName        string
		devCertificateName string
		kid                string
		teamID             string
		clientID           string
		expiration         time.Duration
	)
	flag.StringVar(&outFileName, "o", "", "output filename, if not provided then STDOUT")
	flag.StringVar(&devCertificateName, "dev-certificate", "", "filepath to .p8 file (create Key/certificate: https://developer.apple.com/account/resources/authkeys/list)")
	flag.StringVar(&kid, "kid", "", "10 char kid for certificate (can be found in the https://developer.apple.com/account/resources/authkeys/list -> Key Details")
	flag.StringVar(&teamID, "team-id", "", "10 char team id (can be found next to dev account name)")
	flag.StringVar(&clientID, "client-id", "", "use same App ID or Services ID that use as client_id used to generate refresh tokens")
	flag.DurationVar(&expiration, "expiration", 6*28*24*time.Hour, "expiration time for the token")
	flag.Usage = func() {
		fmt.Print(doc)
		flag.PrintDefaults()
	}
	flag.Parse()

	if teamID == "" || clientID == "" || kid == "" {
		log.Fatalln("missing required arguments")
	}
	if expiration > 28*6*24*time.Hour {
		log.Fatalln("expiration time should be less than 6 months")
	}

	cerFileBytes, err := os.ReadFile(devCertificateName)
	if err != nil {
		log.Fatalln(err)
	}

	privateKey, err := jwt.ParseECPrivateKeyFromPEM(cerFileBytes)
	if err != nil {
		log.Fatalln(err)
	}

	method := jwt.SigningMethodES256
	token := &jwt.Token{
		Method: method,
		Header: map[string]interface{}{
			"typ": "JWT",
			"alg": method.Alg(),
			"kid": kid,
		},
		Claims: jwt.MapClaims{
			"iss": teamID,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(expiration).Unix(),
			"aud": "https://appleid.apple.com",
			"sub": clientID,
		},
	}

	s, err := token.SignedString(privateKey)
	if err != nil {
		log.Fatalln(err)
	}

	var out io.Writer = os.Stdout
	if outFileName != "" {
		outf, err := os.OpenFile(outFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
		if err != nil {
			log.Fatalln(err)
		}
		defer outf.Close()
		out = outf
	}

	if _, err := out.Write([]byte(s)); err != nil {
		log.Fatalln(err)
	}
}

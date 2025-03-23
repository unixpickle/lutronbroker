package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/unixpickle/essentials"
	"github.com/unixpickle/lutronbroker/lutronbroker"
)

func main() {
	var email string
	var password string
	var outPath string
	flag.StringVar(&email, "email", "", "email for user")
	flag.StringVar(&password, "password", "", "password for user")
	flag.StringVar(&outPath, "out-path", "", "path to store output (default to stdout)")
	flag.Parse()

	if email == "" || password == "" {
		essentials.Die("must specify -email and -password flags")
	}

	result, err := lutronbroker.GetOAuthToken(context.Background(), email, password)
	if err != nil {
		essentials.Die(err.Error())
	}
	encoded, err := json.Marshal(result)
	essentials.Must(err)
	if outPath == "" {
		fmt.Println(string(encoded))
	} else {
		essentials.Must(os.WriteFile(outPath, encoded, 0600))
	}
}

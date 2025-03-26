package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/unixpickle/essentials"
	"github.com/unixpickle/lutronbroker/lutronbroker"
)

func main() {
	var oauthToken string
	var outPath string
	flag.StringVar(&oauthToken, "oauth-token", "", "OAuth token path for authentication")
	flag.StringVar(&outPath, "out-path", "", "path to store output (default to stdout)")
	flag.Parse()

	if oauthToken == "" {
		essentials.Die("must specify -oauth-token flag")
	}

	var token *lutronbroker.OAuthToken
	data, err := os.ReadFile(oauthToken)
	essentials.Must(err)
	essentials.Must(json.Unmarshal(data, &token))

	devices, err := lutronbroker.ListDevices(context.Background(), token)
	essentials.Must(err)
	if len(devices) == 0 {
		essentials.Die("must have at least one device")
	} else if len(devices) > 1 {
		log.Println("found more than one device; using the first one.")
	}
	device := devices[0]
	log.Printf("found device %s (%s)", device.FriendlyName, device.SerialNumber)
	brokers, err := lutronbroker.ListDeviceBrokers(context.Background(), token, device.SerialNumber)
	essentials.Must(err)
	if len(brokers) != 1 {
		essentials.Die("must have exactly one device in response")
	}
	if len(brokers[0].AvailableBrokers) == 0 {
		essentials.Die("no brokers found")
	}
	broker := brokers[0].AvailableBrokers[0]

	result, err := lutronbroker.AuthenticateWithBroker(
		context.Background(), token, device.SerialNumber, &broker,
	)
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

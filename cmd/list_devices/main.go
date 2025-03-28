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
	var credPath string
	flag.StringVar(&credPath, "creds", "", "path to broker credentials")
	flag.Parse()

	if credPath == "" {
		essentials.Die("must specify -creds flag")
	}

	data, err := os.ReadFile(credPath)
	essentials.Must(err)
	var creds lutronbroker.BrokerCredentials
	essentials.Must(json.Unmarshal(data, &creds))

	conn, err := lutronbroker.NewBrokerConnection(context.Background(), &creds)
	essentials.Must(err)

	clientTag := "abc" // Unique ID for this message
	callMsg := lutronbroker.Message{
		"CommuniqueType": "ReadRequest",
		"Header": map[string]any{
			"ClientTag": clientTag,
			"Url":       "/device",
		},
	}
	msg, err := conn.Call(
		context.Background(),
		callMsg,
		func(msg lutronbroker.Message) (bool, error) {
			if header, ok := msg["Header"].(map[string]any); ok {
				if clientTag, ok := header["ClientTag"]; ok && clientTag == clientTag {
					return true, nil
				}
			}
			return false, nil
		},
	)
	essentials.Must(err)
	if body, ok := msg["Body"].(map[string]any); !ok {
		essentials.Die("received invalid response")
	} else {
		data, _ := json.Marshal(body)
		fmt.Println(string(data))
	}
}

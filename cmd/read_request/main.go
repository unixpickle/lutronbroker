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

type Header struct {
	ClientTag string
	Url       string
}

type Message struct {
	CommuniqueType string
	Header         Header
	Body           json.RawMessage `json:",omitempty"`
}

func main() {
	var credPath string
	var url string
	flag.StringVar(&credPath, "creds", "", "path to broker credentials")
	flag.StringVar(&url, "url", "/device", "URL to request")
	flag.Parse()

	if credPath == "" {
		essentials.Die("must specify -creds flag")
	}

	data, err := os.ReadFile(credPath)
	essentials.Must(err)
	var creds lutronbroker.BrokerCredentials
	essentials.Must(json.Unmarshal(data, &creds))

	conn, err := lutronbroker.NewBrokerConnection[Message](context.Background(), &creds)
	essentials.Must(err)

	clientTag := "abc" // Unique ID for this message
	callMsg := Message{
		CommuniqueType: "ReadRequest",
		Header: Header{
			ClientTag: clientTag,
			Url:       url,
		},
	}
	msg, err := conn.Call(
		context.Background(),
		callMsg,
		func(msg Message) (bool, error) {
			return msg.Header.ClientTag == clientTag, nil
		},
	)
	essentials.Must(err)
	fmt.Println(string(msg.Body))
}

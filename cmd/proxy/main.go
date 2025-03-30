// Command proxy pretends to be a locally-accessible Lutron bridge, proxying
// LEAP messages back and forth between a local SSL client and Lutron's server.
//
// To create certificates for the server, you can run these commands:
//
//	openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
//	openssl req -new -key private_key.pem -out request.csr
//	openssl x509 -req -days 365 -in request.csr -signkey private_key.pem -out certificate.pem
//
// The server will accept any client certificates, so you may simply do the
// same steps on the client side.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/unixpickle/essentials"
	"github.com/unixpickle/lutronbroker/lutronbroker"
)

type Header struct {
	ClientTag  string
	Url        string
	StatusCode string `json:",omitempty"`
}

type Message struct {
	CommuniqueType string
	Header         Header
	Body           json.RawMessage `json:",omitempty"`
}

func main() {
	var brokerCredsPath string
	var privateKeyPath string
	var serverCertPath string
	var port int
	flag.StringVar(&privateKeyPath, "private-key", "", "server private key")
	flag.StringVar(&serverCertPath, "server-cert", "", "server certificate")
	flag.StringVar(&brokerCredsPath, "broker-creds", "", "path to broker credentials")
	flag.IntVar(&port, "port", 8081, "port to listen on")
	flag.Parse()
	if brokerCredsPath == "" || privateKeyPath == "" || serverCertPath == "" {
		essentials.Die("Must specify -private-key, -server-cert, and -broker-creds")
	}

	var creds *lutronbroker.BrokerCredentials
	data, err := os.ReadFile(brokerCredsPath)
	essentials.Must(err)
	essentials.Must(json.Unmarshal(data, &creds))

	cert, err := tls.LoadX509KeyPair(serverCertPath, privateKeyPath)
	if err != nil {
		log.Fatalf("Failed to load server certificate and key: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	listener, err := tls.Listen("tcp", ":"+strconv.Itoa(port), tlsConfig)
	if err != nil {
		essentials.Die(err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		// NOTE: even though we handle concurrent connections, Lutron's
		// backend will not allow multiple clients and will boot off previous
		// clients when a new one is connected.
		go handleConnection(creds, conn)
	}
}

func handleConnection(creds *lutronbroker.BrokerCredentials, conn net.Conn) {
	defer conn.Close()

	log.Printf("connection from %s", conn.RemoteAddr())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	broker, err := lutronbroker.NewBrokerConnection[Message](ctx, creds)
	if err != nil {
		log.Printf("canceling connection: %v", err)
		return
	}
	defer broker.Close()

	log.Printf("established broker connection")

	go func() {
		defer cancel()
		defer broker.Close()
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			var msg Message
			if err := json.Unmarshal([]byte(line), &msg); err != nil {
				log.Printf("failed to parse JSON request: %s", err.Error())
				return
			}
			log.Printf("forwarding message to broker: %s", strings.TrimSpace(line))
			if err := broker.Send(msg); err != nil {
				log.Printf("failed to forward message to broker: %s", err.Error())
				return
			}
		}
	}()

	incomingChan := make(chan Message, 10)
	go func() {
		defer broker.Close()
		defer cancel()

		writer := bufio.NewWriter(conn)
		for msg := range incomingChan {
			msg.Header.StatusCode = "200 OK"
			data, err := json.Marshal(msg)
			if err != nil {
				log.Printf("failed to marshal message: %s", err.Error())
				return
			}
			log.Printf("forwarding message to client: %s", string(data))
			if _, err := writer.Write(append(data, []byte("\r\n")...)); err != nil {
				log.Printf("failed to forward to client: %s", err.Error())
			}
			if err := writer.Flush(); err != nil {
				log.Printf("failed to forward to client: %s", err.Error())
			}
		}
	}()
	err = broker.Subscribe(ctx, incomingChan)
	log.Printf("disconnected from broker with error %s", err)
}

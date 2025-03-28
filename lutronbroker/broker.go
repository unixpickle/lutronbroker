package lutronbroker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/unixpickle/essentials"
)

var ErrClosed = errors.New("broker connection is closed")

const (
	connectTimeout       = time.Second * 30
	connectTimeoutBuffer = time.Second * 10
)

type Message map[string]any

type subscriber struct {
	incoming chan<- Message
	cancel   <-chan struct{}
}

type BrokerConnection struct {
	conn      mqtt.Client
	sessionID string

	publishTopic string

	// Sent to when we received a connected packet from the remote.
	connectRespChan chan<- struct{}

	doneLock sync.RWMutex
	doneChan chan struct{}
	doneErr  error

	subsLock sync.RWMutex
	subs     map[*subscriber]struct{}
}

func NewBrokerConnection(
	ctx context.Context,
	creds *BrokerCredentials,
) (result *BrokerConnection, err error) {
	defer essentials.AddCtxTo("create broker connection", &err)

	connectRespChan := make(chan struct{}, 1)
	result = &BrokerConnection{
		doneChan:        make(chan struct{}),
		sessionID:       uuid.New().String(),
		publishTopic:    creds.PublishTopic,
		connectRespChan: connectRespChan,
		subs:            map[*subscriber]struct{}{},
	}

	rootCAs, err := parsePEM([]byte(creds.RootCA))
	if err != nil {
		return nil, err
	}
	clientCert, err := tls.X509KeyPair([]byte(creds.DeviceCert), []byte(creds.PrivateKey))
	options := mqtt.NewClientOptions()
	options.SetCleanSession(true)
	options.SetClientID(creds.ClientID)
	options.SetAutoReconnect(false)
	options.SetConnectRetry(false)
	options.SetConnectTimeout(connectTimeout)
	options.SetConnectionLostHandler(func(c mqtt.Client, err error) {
		result.handleConnectionLost(err)
	})
	options.SetTLSConfig(&tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      rootCAs,
	})
	result.conn = mqtt.NewClient(options)
	token := result.conn.Connect()
	select {
	case <-token.Done():
		if token.Error() != nil {
			return nil, token.Error()
		}
	case <-ctx.Done():
		go func() {
			// Kill the connection once the token is completed.
			<-token.Done()
			if token.Error() == nil {
				result.conn.Disconnect(0)
			}
		}()
		return nil, ctx.Err()
	}

	// From now on, when waiting for a Token, we can simply
	// disconnect immediately on context errors.
	waitToken := func(t mqtt.Token) error {
		select {
		case <-t.Done():
			if t.Error() != nil {
				result.Close()
				return t.Error()
			}
		case <-result.doneChan:
			if err := result.Error(); err != nil {
				return err
			} else {
				panic("closed without an error; this should not be possible!")
			}
		case <-ctx.Done():
			result.Close()
			return ctx.Err()
		}
		return nil
	}

	token = result.conn.Subscribe(
		creds.SubscribeTopic,
		2,
		func(client mqtt.Client, msg mqtt.Message) {
			result.handleMessage(msg)
		},
	)
	if err := waitToken(token); err != nil {
		return nil, err
	}

	connData, _ := json.Marshal(map[string]string{
		"session_id":   result.sessionID,
		"message_type": "connect",
	})
	token = result.conn.Publish(creds.PublishTopic, 2, false, connData)
	if err := waitToken(token); err != nil {
		return nil, err
	}

	select {
	case <-connectRespChan:
	case <-result.doneChan:
		if err := result.Error(); err != nil {
			return nil, err
		} else {
			panic("closed without an error; this should not be possible!")
		}
	case <-ctx.Done():
		result.Close()
		return nil, ctx.Err()
	}

	return result, nil
}

// Send asynchronously sends a message to the broker.
//
// It is not guaranteed that the message has been received when this call
// returns, and an error may not be returned even if the message is destined
// to never be received.
func (b *BrokerConnection) Send(msg Message) (err error) {
	defer essentials.AddCtxTo("send to broker", &err)

	// This is not 100% reliable, as the connection might die
	// mid-send.
	select {
	case <-b.doneChan:
		return ErrClosed
	default:
	}

	encoded, err := json.Marshal(map[string]any{
		"session_id": b.sessionID,
		"payload":    msg,
	})
	if err != nil {
		return err
	}
	b.conn.Publish(b.publishTopic, 2, false, encoded)
	return nil
}

// Subscribe listens to messages from the remote end until the context is
// completed, or the connection dies.
//
// This method will always return an error indicating why it returned.
// The error will wrap ErrClosed if the reason is due to the connection
// closing; otherwise it will wrap the context's error.
func (b *BrokerConnection) Subscribe(ctx context.Context, ch chan<- Message) (err error) {
	defer essentials.AddCtxTo("subscribe to broker", &err)
	sub := &subscriber{
		incoming: ch,
		cancel:   ctx.Done(),
	}
	b.subsLock.Lock()
	b.subs[sub] = struct{}{}
	b.subsLock.Unlock()

	defer func() {
		b.subsLock.Lock()
		delete(b.subs, sub)
		b.subsLock.Unlock()
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.doneChan:
		return ErrClosed
	}
}

// Close disconnects from the broker.
func (b *BrokerConnection) Close() (err error) {
	defer essentials.AddCtxTo("close broker", &err)
	b.doneLock.Lock()
	defer b.doneLock.Unlock()
	select {
	case <-b.doneChan:
		return ErrClosed
	default:
	}
	close(b.doneChan)
	b.conn.Disconnect(0)
	return nil
}

// Error returns an error if the connection was closed due to
// external reasons (rather than Close()).
func (b *BrokerConnection) Error() error {
	b.doneLock.RLock()
	defer b.doneLock.RUnlock()
	return b.doneErr
}

func (b *BrokerConnection) handleMessage(m mqtt.Message) {
	// Skip completely if we have been closed.
	select {
	case <-b.doneChan:
		return
	default:
	}

	var parsed struct {
		Message     *Message `json:"payload"`
		MessageType string   `json:"message_type"`
		SessionID   string   `json:"session_id"`
	}

	if json.Unmarshal(m.Payload(), &parsed) != nil {
		return
	}
	if parsed.MessageType == "connected" {
		select {
		case b.connectRespChan <- struct{}{}:
		default:
			// This would only happen if the remote sends more than one
			// connected packet, which we can ignore.
		}
		return
	}
	if parsed.Message == nil {
		return
	}
	msg := *parsed.Message

	b.subsLock.RLock()
	defer b.subsLock.RUnlock()
	for sub := range b.subs {
		select {
		case sub.incoming <- msg:
		case <-b.doneChan:
			return
		default:
			go func() {
				select {
				case sub.incoming <- msg:
				case <-b.doneChan:
					return
				case <-sub.cancel:
					return
				}
			}()
		}
	}
}

func (b *BrokerConnection) handleConnectionLost(err error) {
	b.doneLock.Lock()
	defer b.doneLock.Unlock()
	select {
	case <-b.doneChan:
		return
	default:
	}
	b.doneErr = err
	close(b.doneChan)
}

func parsePEM(pemData []byte) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemData) {
		return nil, errors.New("no certificates found in PEM")
	}
	return certPool, nil
}

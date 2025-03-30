# lutronbroker

This is a Go API for establishing connections to Lutron devices over the internet.

# Background

When you use the Lutron app to access your IoT devices outside of your own WiFi network, the app authenticates with Lutron's server and uses this server to proxy [LEAP](https://support.lutron.com/us/en/product/radiora3/article/networking/Lutron-s-LEAP-API-Integration-Protocol) messages to and from your Lutron bridge.

I reverse engineered the Lutron app to implement a simple API around this connection process. Internally, the authentication is performed via HTTPS in two steps; then, another HTTPS call is used to sign a generated certificate; finally, an [MQTT](https://mqtt.org/) connection is established over which LEAP messages are tunneled.

# Proxy end-to-end usage

The simplest use case of this package is creating a proxy through which existing LEAP APIs can communicate with your Lutron devices over the internet. Typically, existing LEAP APIs want to connect to a Lutron bridge directly on your network. With the [cmd/proxy](cmd/proxy) tool, you can now use any of these APIs without requiring local network access.

First, create an OAuth token and broker credentials:

```
go run ./cmd/get_oauth_token -email <your email> -password "<your password>" -out-path token.json
go run ./cmd/auth_with_broker -oauth-token token.json -out-path broker_creds.json
```

Next, create a private key and certificate any way you like, for example

```
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
openssl req -new -key private_key.pem -out request.csr
openssl x509 -req -days 365 -in request.csr -signkey private_key.pem -out certificate.pem
```

Finally, run a proxy listening on `localhost:8081`

```
go run ./cmd/proxy -broker-creds broker_creds.json -private-key private_key.pem -server-cert certificate.pem
```

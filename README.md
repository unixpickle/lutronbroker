# lutronbroker

This is a Go API for establishing connections to Lutron devices over the internet.

# Background

When you use the Lutron app to access your IoT devices outside of your own WiFi network, the app authenticates with Lutron's server and uses this server to proxy [LEAP](https://support.lutron.com/us/en/product/radiora3/article/networking/Lutron-s-LEAP-API-Integration-Protocol) messages to and from your Lutron bridge.

I reverse engineered the Lutron app to implement a simple API around this connection process. Internally, the authentication is performed via HTTPS in two steps; then, another HTTPS call is used to sign a generated certificate; finally, an [MQTT](https://mqtt.org/) connection is established over which LEAP messages are tunneled.

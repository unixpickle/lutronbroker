package lutronbroker

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"

	"github.com/unixpickle/essentials"
)

// DeviceBrokerInfo describes the available brokers for a divec.
// Device represents an individual device
type DeviceBrokerInfo struct {
	MacAddress       string   `json:"mac_address"`
	DeviceType       string   `json:"device_type"`
	DeviceID         string   `json:"device_id"`
	AvailableBrokers []Broker `json:"available_brokers"`
}

// Broker represents the available broker information
type Broker struct {
	BrokerIdentifier  string            `json:"broker_identifier"`
	BrokerType        string            `json:"broker_type"`
	MQTTParams        MQTTBrokerParams  `json:"mqtt_broker_parameters"`
	ClientCertificate ClientCertificate `json:"client_certificate"`
	ETag              string            `json:"etag"`
	Priority          int               `json:"priority"`
}

// MQTTBrokerParams represents MQTT broker-specific parameters
type MQTTBrokerParams struct {
	MQTTBrokerType string `json:"mqtt_broker_type"`
}

// ClientCertificate stores the information needed to create a CSR for
// connecting to a broker.
type ClientCertificate struct {
	Subject struct {
		CommonName   string   `json:"cn"`
		Country      []string `json:"country"`
		Organization []string `json:"organization"`
		Locality     []string `json:"locality"`
		Province     []string `json:"province"`
	} `json:"subject"`
}

func (c *ClientCertificate) subject(local bool) pkix.Name {
	var result pkix.Name
	if local {
		result.CommonName = "Lutron App"
	} else {
		result.CommonName = c.Subject.CommonName
	}
	result.Country = c.Subject.Country
	result.Organization = c.Subject.Organization
	result.Locality = c.Subject.Locality
	result.Province = c.Subject.Province
	return result
}

// ListDeviceBrokers gets a list of brokers for the device.
func ListDeviceBrokers(token *OAuthToken, macAddr string) (devices []DeviceBrokerInfo, err error) {
	defer essentials.AddCtxTo("list device brokers", &err)

	var body struct {
		ClientAppID string `json:"client_app_identifier"`
		MacAddr     string `json:"mac_address"`
	}
	body.ClientAppID = clientAppIdentifier
	body.MacAddr = macAddr
	err = postJSON(token, provisioningClientURL, body, &devices)
	return
}

// BrokerCredentials contains all of the information needed to authenticate
// with an MQTT broker.
type BrokerCredentials struct {
	PrivateKey *rsa.PrivateKey
	DeviceCert string
	RootCA     string

	ClientID       string
	URL            string
	SubscribeTopic string
	PublishTopic   string
}

// AuthenticateWithBroker performs the steps needed to authenticate with
// a broker, returning the resulting credentials.
func AuthenticateWithBroker(token *OAuthToken, macAddr string, b *Broker) (creds *BrokerCredentials, err error) {
	defer essentials.AddCtxTo("authenticate with broker", &err)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	localReq, err := csrPem(privateKey, b.ClientCertificate.subject(true))
	if err != nil {
		return nil, err
	}
	brokerReq, err := csrPem(privateKey, b.ClientCertificate.subject(false))
	if err != nil {
		return nil, err
	}

	type PEMContainer struct {
		PEM string `json:"pem"`
	}

	type CSRContainer struct {
		CSR PEMContainer `json:"csr"`
	}

	type ProvisionedBroker struct {
		Priority          int          `json:"priority"`
		BrokerIdentifier  string       `json:"broker_identifier"`
		ClientCertificate CSRContainer `json:"client_certificate"`
	}

	type Device struct {
		LocalAccessCert    CSRContainer        `json:"local_access_cert"`
		MacAddr            string              `json:"mac_address"`
		ProvisionedBrokers []ProvisionedBroker `json:"provisioned_brokers"`
	}

	type CSRRequest struct {
		Devices             []Device `json:"devices"`
		ClientAppIdentifier string   `json:"client_app_identifier"`
	}

	req := CSRRequest{
		Devices: []Device{
			{
				LocalAccessCert: CSRContainer{CSR: PEMContainer{PEM: localReq}},
				MacAddr:         macAddr,
				ProvisionedBrokers: []ProvisionedBroker{
					{
						Priority:          0,
						BrokerIdentifier:  b.BrokerIdentifier,
						ClientCertificate: CSRContainer{CSR: PEMContainer{PEM: brokerReq}},
					},
				},
			},
		},
	}

	type ResponseCertificate struct {
		Leaf PEMContainer `json:"leaf"`
	}

	type ResponseURL struct {
		Scheme                   string `json:"scheme"`
		Hostname                 string `json:"hostname"`
		Port                     int    `json:"port"`
		ApplicationLayerProtocol string `json:"application_layer_protocol,omitempty"`
	}

	type ResponseTopicDetails struct {
		RequestTopicPrefix        string `json:"request_topic_prefix"`
		ResponseTopicFilterPrefix string `json:"response_topic_filter_prefix"`
	}

	type ResponseClientTopics struct {
		LEAP ResponseTopicDetails `json:"leap"`
	}

	type ResponseAWSIoTCoreParameters struct {
		ClientTopics ResponseClientTopics `json:"client_topics"`
	}

	type ResponseMQTTBrokerParameters struct {
		ClientIdentifier string                        `json:"client_identifier"`
		BrokerType       string                        `json:"mqtt_broker_type"`
		AWSIoTCoreParams *ResponseAWSIoTCoreParameters `json:"aws_iot_core_broker_parameters"`
	}

	type ResponseBroker struct {
		BrokerIdentifier  string                       `json:"broker_identifier"`
		BrokerType        string                       `json:"broker_type"`
		MQTTBrokerParams  ResponseMQTTBrokerParameters `json:"mqtt_broker_parameters"`
		ClientCertificate ResponseCertificate          `json:"client_certificate"`
		URLs              []ResponseURL                `json:"urls"`
		RootOfTrust       ResponseCertificate          `json:"root_of_trust"`
	}

	type ResponseDevice struct {
		MACAddress         string           `json:"mac_address"`
		DeviceID           string           `json:"device_id"`
		DeviceType         string           `json:"device_type"`
		ProvisionedBrokers []ResponseBroker `json:"provisioned_brokers"`
	}

	type ResponseRoot struct {
		Devices []ResponseDevice `json:"devices"`
	}

	var response ResponseRoot
	if err := postJSON(token, provisioningClientURL, req, &response); err != nil {
		return nil, err
	}

	if len(response.Devices) != 1 || len(response.Devices[0].ProvisionedBrokers) < 1 {
		return nil, fmt.Errorf("unexpected number of devices or brokers in response")
	}
	brokerInfo := response.Devices[0].ProvisionedBrokers[0]
	if brokerInfo.MQTTBrokerParams.AWSIoTCoreParams == nil {
		return nil, fmt.Errorf("unable to find AWS broker parameters in response")
	}
	if len(brokerInfo.URLs) < 1 {
		return nil, fmt.Errorf("unable to find broker URLs in response")
	}

	deviceCert := brokerInfo.ClientCertificate.Leaf.PEM
	rootCA := brokerInfo.RootOfTrust.Leaf.PEM
	return &BrokerCredentials{
		PrivateKey:     privateKey,
		DeviceCert:     deviceCert,
		RootCA:         rootCA,
		ClientID:       brokerInfo.MQTTBrokerParams.ClientIdentifier,
		URL:            fmt.Sprintf("ssl://%s:%d", brokerInfo.URLs[0].Hostname, brokerInfo.URLs[0].Port),
		SubscribeTopic: brokerInfo.MQTTBrokerParams.AWSIoTCoreParams.ClientTopics.LEAP.ResponseTopicFilterPrefix + "/ComMgr",
		PublishTopic:   brokerInfo.MQTTBrokerParams.AWSIoTCoreParams.ClientTopics.LEAP.RequestTopicPrefix + "/ComMgr",
	}, nil
}

func csrPem(privateKey *rsa.PrivateKey, subj pkix.Name) (string, error) {
	csr := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csr, privateKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})), nil
}

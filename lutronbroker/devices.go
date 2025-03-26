package lutronbroker

import (
	"context"
	"encoding/json"

	"github.com/unixpickle/essentials"
)

// DeviceInfo describes a device returned by ListDevices().
type DeviceInfo struct {
	SerialNumber string `json:"serialnumber"`
	DeviceType   string `json:"device_type"`
	FriendlyName string `json:"friendly_name"`
}

// ListDevices asks the server to list root devices.
//
// A device can then be used in future calls to get and connect to a broker.
func ListDevices(ctx context.Context, token *OAuthToken) (devices []*DeviceInfo, err error) {
	defer essentials.AddCtxTo("list devices", &err)
	resp, err := getWithToken(ctx, token, devicesURL)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(resp, &devices); err != nil {
		return nil, err
	}
	return
}

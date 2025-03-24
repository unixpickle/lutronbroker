package lutronbroker

const (
	signInBase     = "https://device-login.lutron.com/oauth/authorize"
	signInOAuthURL = "https://device-login.lutron.com/oauth/token"

	// Defined in com.lutron.mmw.BaseApplication
	signInClientID     = "e001a4471eb6152b7b3f35e549905fd8589dfcf57eb680b6fb37f20878c28e5a"
	signInClientSecret = "b07fee362538d6df3b129dc3026a72d27e1005a3d1e5839eed5ed18c63a89b27"

	// Could possibly be anything, but this is what the app chose
	signInRedirect = "https://device-login.lutron.com/integration/authorization/logo"

	devicesURL = "https://device-login.lutron.com/api/v1/users/devices"
)

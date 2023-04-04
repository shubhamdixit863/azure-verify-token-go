package azure

import (
	"context"
	"fmt"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
	"github.com/lestrrat-go/jwx/jwk"
)

type Auth struct {
	discoveryKeysEndPoint string
	clientId              string
	authority             string
	clientSecret          string
}

func NewAuth(discoveryKeysEndPoint, clientId, authority, clientSecret string) *Auth {
	return &Auth{
		discoveryKeysEndPoint,
		clientId,
		authority,
		clientSecret,
	}
}

func (auth *Auth) createConfidentialClient() (*confidential.Client, error) {

	// Initializing the client credential
	cred, err := confidential.NewCredFromSecret(auth.clientSecret)
	if err != nil {
		return nil, fmt.Errorf("could not create a cred from a secret: %w", err)
	}
	confidentialClientApp, err := confidential.New(auth.authority, auth.clientId, cred)
	return &confidentialClientApp, nil
}

func (auth *Auth) LoadSigningKeys(kid string) (jwk.Key, error) {
	set, err := jwk.Fetch(context.Background(), auth.discoveryKeysEndPoint)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch jwks: %w", err)
	}

	key, ok := set.LookupKeyID(kid)
	if !ok {
		return nil, errors.New("kid not found in jwks")
	}

	// Extract the RSA public key from the JWK
	rsaKey, err := key.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get Public Key jwk: %w", err)
	}
	return rsaKey, nil
}

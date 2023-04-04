package test

import (
	"fmt"
	"github.com/joho/godotenv"
	"github.com/shubhamdixit863/azure-verify-token-go/src/azure"
	"github.com/stretchr/testify/assert"
	"log"
	"os"
	"testing"
)

func TestNewAuth(t *testing.T) {
	err := godotenv.Load("../.env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	auth := azure.NewAuth(os.Getenv("discoveryKeysEndPoint"), os.Getenv("clientId"), os.Getenv("authority"), os.Getenv("clientSecret"))
	assert.NotNil(t, auth)
}

func TestLoadSigningKeys(t *testing.T) {
	publicKey, err := azure.NewAuth(os.Getenv("discoveryKeysEndPoint"), os.Getenv("clientId"), os.Getenv("authority"), os.Getenv("clientSecret")).LoadSigningKeys("DFAClwwOwJWpDVvVxj8pEw2KY9o2BkplOr5jmYI62Qk")
	fmt.Println(publicKey)
	assert.Nil(t, err)
	assert.NotNil(t, publicKey)

}

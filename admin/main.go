package admin

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kloudlite/container-registry-authorizer/env"
)

// getExpirationTime returns the time.Time object for the given expiration string
func getExpirationTime(expiration string) (time.Time, error) {
	now := time.Now()

	if len(expiration) != 2 {
		return now, fmt.Errorf("invalid expiration format, please use '1h', '1d', '1w', '1m', '1y'")
	}

	durationVal := expiration[0]  // '1' in '1h', '1d', '1w', '1m', '1y'
	durationType := expiration[1] // 'h', 'd', 'w', 'm', 'y'

	switch durationType {
	case 'h':
		return now.Add(time.Duration(durationVal-'0') * time.Hour), nil
	case 'd':
		return now.AddDate(0, 0, int(durationVal-'0')), nil
	case 'w':
		return now.AddDate(0, 0, int(durationVal-'0')*7), nil
	case 'm':
		return now.AddDate(0, int(durationVal-'0'), 0), nil
	case 'y':
		return now.AddDate(int(durationVal-'0'), 0, 0), nil
	default:
		return now, fmt.Errorf("invalid duration type: %v", durationType)
	}
}

// nonce generates a random string of length size
func nonce(size int) string {
	chars := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	nonceBytes := make([]byte, size)

	for i := range nonceBytes {
		nonceBytes[i] = chars[rand.Intn(len(chars))]
	}

	return string(nonceBytes)
}

// GenerateToken generates a token with the given username, accountname, access and expiry expiry string shoud be in RFC3339[ example: 2023-09-16T23:03:52+05:30 ] format
func GenerateToken(userName, accountName, access string, expiry time.Time) string {
	nonce := nonce(5)
	body := userName + "::" + accountName + "::" + access + "::" + expiry.Format(time.RFC3339) + "::" + nonce
	secretKey := os.Getenv("SECRET_KEY")

	bodyWithSecret := body + "::" + secretKey

	token := hex.EncodeToString(sha256.New().Sum([]byte(bodyWithSecret)))

	resp := base64.StdEncoding.EncodeToString([]byte(body + "::" + token))

	return resp
}

func StartServer(envs *env.Envs) error {
	iApp := fiber.New()
	iApp.Post(".secret/generate-token", func(c *fiber.Ctx) error {
		type Body struct {
			UserName    string `json:"username"`
			AccountName string `json:"accountname"`
			Access      string `json:"access"`
			Expiration  string `json:"expiration"`
		}

		var body Body
		if err := c.BodyParser(&body); err != nil {
			return err
		}

		expirationTime, err := getExpirationTime(body.Expiration)
		if err != nil {
			return err
		}

		token := GenerateToken(body.UserName, body.AccountName, body.Access, expirationTime)
		return c.Send([]byte(token))
	})

	port := fmt.Sprintf(":%d", func() int {
		if envs.AdminServerPort == 0 {
			return 4000
		}
		return envs.AdminServerPort
	}())

	fmt.Println("Admin server starting on port: ", port)
	if err := iApp.Listen(port); err != nil {
		return err
	}
	return nil
}

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/basicauth"
	"github.com/kloudlite/container-registry-authorizer/env"
)

// nonce generates a random string of length size
func nonce(size int) string {
	chars := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	nonceBytes := make([]byte, size)

	for i := range nonceBytes {
		nonceBytes[i] = chars[rand.Intn(len(chars))]
	}

	return string(nonceBytes)
}

// parseAndVerifyToken parses the token and verifies it with the secret key and returns the username, accountname, access and error
func parseAndVerifyToken(password string) (userName, accountName, access string, err error) {

	tokenString, err := base64.StdEncoding.DecodeString(password)
	if err != nil {
		return "", "", "", err
	}
	tokenArray := strings.Split(string(tokenString), "::")

	if len(tokenArray) != 6 {
		return "", "", "", fmt.Errorf("Invalid token")
	}
	userName, accountName, access, expiryString, nonce, oldToken := tokenArray[0], tokenArray[1], tokenArray[2], tokenArray[3], tokenArray[4], tokenArray[5]

	expiry, err := time.Parse(time.RFC3339, expiryString)
	if err != nil {
		return "", "", "", err
	}

	if expiry.Before(time.Now()) {
		return "", "", "", fmt.Errorf("Token expired")
	}

	secretKey := os.Getenv("SECRET_KEY")

	body := userName + "::" + accountName + "::" + access + "::" + expiryString + "::" + nonce
	bodyWithSecret := body + "::" + secretKey
	newToken := hex.EncodeToString(sha256.New().Sum([]byte(bodyWithSecret)))

	if oldToken != newToken {
		return "", "", "", fmt.Errorf("Invalid token")
	}

	return userName, accountName, access, nil
}

// generateToken generates a token with the given username, accountname, access and expiry expiry string shoud be in RFC3339[ example: 2023-09-16T23:03:52+05:30 ] format
func generateToken(userName, accountName, access string, expiry time.Time) string {
	nonce := nonce(5)
	body := userName + "::" + accountName + "::" + access + "::" + expiry.Format(time.RFC3339) + "::" + nonce
	secretKey := os.Getenv("SECRET_KEY")

	bodyWithSecret := body + "::" + secretKey

	token := hex.EncodeToString(sha256.New().Sum([]byte(bodyWithSecret)))

	resp := base64.StdEncoding.EncodeToString([]byte(body + "::" + token))

	return resp
}

func startAdminServer(envs *env.Envs) error {
	iApp := fiber.New()
	iApp.Post(".secret/generate-token", func(c *fiber.Ctx) error {
		type Body struct {
			UserName    string    `json:"username"`
			AccountName string    `json:"accountname"`
			Access      string    `json:"access"`
			Expiry      time.Time `json:"expiry"`
		}

		var body Body
		if err := c.BodyParser(&body); err != nil {
			return err
		}

		token := generateToken(body.UserName, body.AccountName, body.Access, body.Expiry)
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

func startAuthServer(envs *env.Envs) error {
	app := fiber.New()

	app.Use(":accountname/*", func(c *fiber.Ctx) error {
		accountname := c.Params("accountname", "nan")
		b_auth := basicauth.New(basicauth.Config{
			Realm: "Forbidden",
			Authorizer: func(u string, p string) bool {

				userName, accountName, access, err := parseAndVerifyToken(p)
				if err != nil {
					fmt.Println(err)
					return false
				}

				if (accountName == accountname) && (userName == u) {
					if c.Method() != "GET" {
						if access == "read-write" {
							return true
						}
						return false
					}

					return true
				}

				return false
			},
		})

		return b_auth(c)
	})

	app.Get(":accountname/*", func(c *fiber.Ctx) error {
		return c.SendStatus(200)
	})

	app.Get("/*", func(c *fiber.Ctx) error {
		return c.SendStatus(400)
	})

	port := fmt.Sprintf(":%d", func() int {
		if envs.AuthServerPort == 0 {
			return 3000
		}
		return envs.AuthServerPort
	}())

	fmt.Println("Auth server starting on port: ", port)
	if err := app.Listen(port); err != nil {
		return err
	}

	return nil
}

func main() {
	// ensure that the SECRET_KEY is set
	envs := env.GetEnvsOrDie()

	go func() {
		if err := startAdminServer(envs); err != nil {
			panic(err)
		}
	}()

	err := startAuthServer(envs)
	if err != nil {
		panic(err)
	}
}

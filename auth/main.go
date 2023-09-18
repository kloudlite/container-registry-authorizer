package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/basicauth"
	"github.com/kloudlite/container-registry-authorizer/env"
)

// ParseAndVerifyToken parses the token and verifies it with the secret key and returns the username, accountname, access and error
func ParseAndVerifyToken(password string) (userName, accountName, access string, err error) {

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

func FiberAuthHandler(c *fiber.Ctx) error {
	log.Println("FiberAuthHandler: ", c.OriginalURL())
	path := c.Query("path", "/")
	method := c.Method("path", "GET")

	b_auth := basicauth.New(basicauth.Config{
		Realm: "Forbidden",
		Authorizer: func(u string, p string) bool {
			resp := func() bool {

				userName, accountName, access, err := ParseAndVerifyToken(p)
				if err != nil {
					fmt.Println(err)
					return false
				}

				pathArray := strings.Split(path, "/")

				if len(pathArray) <= 1 {
					return true
				}

				if path == "/v2/" && method == "GET" && userName == u {
					return true
				}

				if len(pathArray) <= 3 {
					return false
				}

				accountname := pathArray[2]

				if (accountName == accountname) && (userName == u) {
					if method != "GET" {
						if access == "read-write" {
							return true
						}
						return false
					}

					return true
				}

				return false
			}()

			log.Println(method, ":", resp, u, path)

			return resp
		},
	})

	return b_auth(c)
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func authorized(w http.ResponseWriter) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func HttpAuthHandler(accountname string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		u, p, ok := r.BasicAuth()
		if !ok {
			unauthorized(w)
			return
		}

		userName, accountName, access, err := ParseAndVerifyToken(p)
		if err != nil {
			fmt.Println(err)
			unauthorized(w)
			return
		}

		if (accountName == accountname) && (userName == u) {
			if r.Method != "GET" {
				if access == "read-write" {
					authorized(w)
					return
				}
				unauthorized(w)
				return
			}

			authorized(w)
			return
		}

		unauthorized(w)
		return

	})
}

func StartServer(envs *env.Envs) error {
	app := fiber.New()

	app.Use(FiberAuthHandler)
	app.Get("/*", func(c *fiber.Ctx) error {
		return c.SendStatus(200)
	})

	port := fmt.Sprintf(":%d", func() int {
		if envs.AuthServerPort == 0 {
			return 3000
		}
		return envs.AuthServerPort
	}())

	log.Println("Auth server starting on port: ", port)
	if err := app.Listen(port); err != nil {
		return err
	}

	return nil
}

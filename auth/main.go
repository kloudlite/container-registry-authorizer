package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/basicauth"
	"github.com/kloudlite/container-registry-authorizer/env"
)

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func authorized(w http.ResponseWriter) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// ParseToken parses the token and returns the username, accountname, access and error
func ParseToken(password string) (userName, accountName, access string, err error) {
	tokenString, err := base64.StdEncoding.DecodeString(password)
	if err != nil {
		return "", "", "", err
	}
	tokenArray := strings.Split(string(tokenString), "::")

	if len(tokenArray) != 6 {
		return "", "", "", fmt.Errorf("Invalid token")
	}
	userName, accountName, access = tokenArray[0], tokenArray[1], tokenArray[2]

	return userName, accountName, access, nil
}

// ParseAndVerifyToken parses the token and verifies it with the secret key and returns the username, accountname, access and error
func ParseAndVerifyToken(password string, secretKey string) (userName, accountName, access string, err error) {

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

	body := userName + "::" + accountName + "::" + access + "::" + expiryString + "::" + nonce
	bodyWithSecret := body + "::" + secretKey
	newToken := hex.EncodeToString(sha256.New().Sum([]byte(bodyWithSecret)))

	if oldToken != newToken {
		return "", "", "", fmt.Errorf("Wrong token")
	}

	return userName, accountName, access, nil
}

func Authorizer(u, p, path, method, secretKey string) error {

	pathArray := strings.Split(path, "/")

	userName, accountName, access, err := ParseAndVerifyToken(p, secretKey)
	if err != nil {
		return err
	}

	if path == "/v2/" && method == "GET" && userName == u {
		return nil
	}

	if len(pathArray) <= 3 {
		return fmt.Errorf("Invalid path: %s", path)
	}

	if len(pathArray) > 3 {
		// Define regex pattern
		pattern := `\/v2\/.*[^\/]\/.*\/(blobs.*|manifests.*)$`

		// Compile the regex pattern
		re, err := regexp.Compile(pattern)
		if err != nil {
			log.Println(err)
		}

		if !re.MatchString(path) {
			return fmt.Errorf("Invalid path %s", path)
		}
	}

	accountname := pathArray[2]

	if (accountName == accountname) && (userName == u) {
		if method != "GET" {
			if access == "read_write" {
				return nil
			}
			return fmt.Errorf("Invalid access")
		}

		return nil
	}

	return fmt.Errorf("Unauthorized Token")
}

func FiberAuthHandler(c *fiber.Ctx, secretKey string) error {
	path := c.Query("path", "/")
	method := c.Query("method", "GET")

	b_auth := basicauth.New(basicauth.Config{
		Realm: "Forbidden",
		Authorizer: func(u string, p string) bool {

			if err := Authorizer(u, p, path, method, secretKey); err != nil {
				log.Println(err)
				return false
			}
			return true
		},
	})

	return b_auth(c)
}

func HttpAuthHandler(accountname string, secretKey string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok {
			unauthorized(w)
			return
		}

		queryParams := r.URL.Query()

		path := queryParams.Get("path")
		method := queryParams.Get("method")

		if err := Authorizer(u, p, path, method, secretKey); err != nil {
			log.Println(err)
			unauthorized(w)
			return
		}

		authorized(w)
		return
	})
}

func StartServer(envs *env.Envs) error {
	app := fiber.New()

	app.Use(func(c *fiber.Ctx) error {
		return FiberAuthHandler(c, envs.SecretKey)
	})
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

package examples

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/kloudlite/container-registry-authorizer/admin"
	"github.com/kloudlite/container-registry-authorizer/auth"
	"github.com/kloudlite/container-registry-authorizer/env"
)

func MuxAuthServer(envs *env.Envs) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		accountname := ""
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) > 1 {
			accountname = parts[1]
		} else {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		auth.HttpAuthHandler(accountname, envs.SecretKey)(w, r)
	})

	port := fmt.Sprintf(":%d", func() int {
		if envs.AuthServerPort == 0 {
			return 3001
		}
		return envs.AuthServerPort + 1
	}())

	srv := &http.Server{
		Addr:         port,
		Handler:      mux,
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Printf("starting mux server on %s", srv.Addr)
	if err := srv.ListenAndServe(); err != nil {
		return err
	}
	return nil
}

func FiberAuthServer(envs *env.Envs) error {
	return auth.StartServer(envs)
}

func RunExample() {
	envs := env.GetEnvsOrDie()
	go func() {
		// start admin server
		if err := admin.StartServer(envs); err != nil {
			panic(err)
		}
	}()

	go func() {
		// fiber auth server
		if err := FiberAuthServer(envs); err != nil {
			panic(err)
		}
	}()

	// mux auth server
	if err := MuxAuthServer(envs); err != nil {
		panic(err)
	}
}

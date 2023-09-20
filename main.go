package main

import (
	"github.com/kloudlite/container-registry-authorizer/admin"
	"github.com/kloudlite/container-registry-authorizer/auth"
	"github.com/kloudlite/container-registry-authorizer/env"
)

func main() {
	envs := env.GetEnvsOrDie()

	go func() {
		if err := admin.StartServer(envs); err != nil {
			panic(err)
		}
	}()

	err := auth.StartServer(envs)
	if err != nil {
		panic(err)
	}
}

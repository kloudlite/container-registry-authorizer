package env

import (
	"github.com/codingconcepts/env"
)

type Envs struct {
	SecretKey       string `env:"SECRET_KEY" required:"true"`
	AdminServerPort int    `env:"ADMIN_SERVER_PORT"`
	AuthServerPort  int    `env:"AUTH_SERVER_PORT"`
}

func GetEnvsOrDie() *Envs {
	var ev Envs
	if err := env.Set(&ev); err != nil {
		panic(err)
	}
	return &ev
}

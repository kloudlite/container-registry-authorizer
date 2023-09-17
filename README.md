# Container Registry Authorizer Server

A simple and efficient container registry authorizer server written in Go.

## Overview

This project provides an easy way to authorize access to your container registry, ensuring secure and controlled access to your images.

## Usage Guide

You can run the server by providing the following environment variables:

- `ADMIN_SERVER_PORT`(optional): The port to run the server on. Defaults to `4000`.
- `AUTH_SERVER_PORT`(optional): The port to run the server on. Defaults to `3000`.
- `SECRET_KEY`(optional): The secret key to use for auth mechanism.

### API Endpoints
- `:accountname/*`: this endpoint is used to authorize access to the registry. It is called by the registry server when a user tries to pull an image. The server checks if the user is authorized to pull the image and returns a `200` if the user is authorized, and a `401` if the user is not authorized.

- `.secret/generate-token`: this endpoint is used to generate a token(password) for a user.
    - `username`: the username of the user to generate a token for.
    - `accountname`: the accountname of the user to generate a token for.
    - `access`: the access level of the user. Can be `read` or `read-write`.
    - `expiration`: the expiration time of the token. Can be `1h`, `1d`, `1w`, `1m`, `1y`.

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

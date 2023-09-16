# Container Registry Authorizer Server

A simple and efficient container registry authorizer server written in Go.

## Overview

This project provides an easy way to authorize access to your container registry, ensuring secure and controlled access to your images.

## Features

- **No Database**: No database is required to run this server.
- **Easy Setup**: The server can be easily set up and configured.

## Usage Guide

You can run the server by providing the following environment variables:

- `ADMIN_SERVER_PORT`(optional): The port to run the server on. Defaults to `4000`.
- `AUTH_SERVER_PORT`(optional): The port to run the server on. Defaults to `3000`.
- `SECRET_KEY`(optional): The secret key to use for auth mechanism.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

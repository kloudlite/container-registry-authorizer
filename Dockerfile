FROM golang:alpine3.18 AS base
USER 1001
ENV GOPATH=/tmp/go
ENV GOCACHE=/tmp/go-cache
WORKDIR /tmp/app
COPY --chown=1001 ./go.mod ./go.sum ./
RUN go mod download -x
COPY --chown=1001 ./  ./
RUN go build -o /tmp/bin/server ./main.go
RUN chmod +x /tmp/bin/server

FROM gcr.io/distroless/static-debian11:nonroot
COPY --from=base --chown=1001 /tmp/bin/server ./server
CMD ["./server"]

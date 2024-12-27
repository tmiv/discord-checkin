FROM golang:1.23-bullseye AS builder

WORKDIR /go/src/app
COPY go.mod go.sum .
RUN go get -d ./...
RUN go mod download 
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 /usr/local/go/bin/go build -o app .

FROM gcr.io/distroless/base:latest

COPY --from=builder /go/src/app/app /usr/local/bin/app

CMD ["/usr/local/bin/app"]

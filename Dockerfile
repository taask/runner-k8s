FROM golang:1.11.2 as builder

RUN mkdir -p /go/src/github.com/taask/runner-k8s
WORKDIR /go/src/github.com/taask/runner-k8s

COPY . .

RUN go build

FROM debian:stable-slim

RUN mkdir -p /taask

COPY --from=builder /go/src/github.com/taask/runner-k8s/runner-k8s /taask/runner-k8s
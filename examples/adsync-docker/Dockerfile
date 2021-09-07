# syntax=docker/dockerfile:1

##
## Build
##
FROM golang:1.17-alpine AS build

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY adsyncer.go ./

RUN go build -o /adsyncer

##
## Deploy
##
FROM golang:1.17-alpine

WORKDIR /

COPY --from=build /adsyncer /adsyncer

ENTRYPOINT ["/adsyncer"]
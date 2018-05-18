all: build deploy-dev deploy-prod
.PHONY: all

build:
	dep ensure
	rm -f bin/*
	env GOOS=linux go build -ldflags="-s -w" -o bin/handler handler/main.go

deploy-dev: build
	sls deploy --stage=dev

deploy-prod:
	sls deploy --stage=prod
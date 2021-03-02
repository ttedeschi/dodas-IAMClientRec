PHONY: build push

all: build

build:
	go build .
	docker build . -t dodasts/dodas-iam-client-rec:`git describe --tags --always`

push: build
	docker push dodasts/dodas-iam-client-rec:`git describe --tags --always`

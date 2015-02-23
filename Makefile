all : build

push: all
	docker push ulexus/jsonip

build:
	CGO_ENABLED=0 GOOS=linux go build -o jsonip -a -installsuffix cgo .
	docker build -t ulexus/jsonip ./

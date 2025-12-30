#!/bin/bash

set -e

# Generate Swagger documentation
echo "Generating Swagger documentation..."
swag init -g doc.go -o ./httpapi/docs --outputTypes json --dir ./httpapi

# Build cryptopro_extract CLI
echo "Building cryptopro_extract..."

# Linux
export GOOS=linux && export GOARCH=amd64 && export CGO_ENABLED=0 && \
go build -ldflags "-s -w" -o cryptopro_extract -gcflags "all=-trimpath=$GOPATH" -trimpath cmd/cryptopro_extract/main.go && \
tar -czvf linux-amd64-cryptopro_extract.tar.gz cryptopro_extract && \
rm cryptopro_extract

# Windows
export GOOS=windows && export GOARCH=amd64 && export CGO_ENABLED=0 && \
go build -ldflags "-s -w" -o cryptopro_extract.exe -gcflags "all=-trimpath=$GOPATH" -trimpath cmd/cryptopro_extract/main.go && \
zip windows-amd64-cryptopro_extract.zip cryptopro_extract.exe && \
rm cryptopro_extract.exe

# Build cryptopro_extract_service HTTP API
echo "Building cryptopro_extract_service..."

# Linux
export GOOS=linux && export GOARCH=amd64 && export CGO_ENABLED=0 && \
go build -ldflags "-s -w" -o cryptopro_extract_service -gcflags "all=-trimpath=$GOPATH" -trimpath cmd/cryptopro_extract_service/main.go && \
tar -czvf linux-amd64-cryptopro_extract_service.tar.gz cryptopro_extract_service && \
rm cryptopro_extract_service

# Windows
export GOOS=windows && export GOARCH=amd64 && export CGO_ENABLED=0 && \
go build -ldflags "-s -w" -o cryptopro_extract_service.exe -gcflags "all=-trimpath=$GOPATH" -trimpath cmd/cryptopro_extract_service/main.go && \
zip windows-amd64-cryptopro_extract_service.zip cryptopro_extract_service.exe && \
rm cryptopro_extract_service.exe

# Build Docker images
echo "Building Docker images..."
docker build -f Dockerfile.cli -t cryptopro-extract:latest .
docker build -f Dockerfile.service -t cryptopro-extract-service:latest .

# push to docker registry
# VERSION=0.0.1
# docker tag cryptopro-extract:latest dimahkiin/cryptopro-extract:${VERSION}
# docker tag cryptopro-extract:latest dimahkiin/cryptopro-extract:latest
# docker tag cryptopro-extract-service:latest dimahkiin/cryptopro-extract-service:${VERSION}
# docker tag cryptopro-extract-service:latest dimahkiin/cryptopro-extract-service:latest
# docker push dimahkiin/cryptopro-extract:${VERSION}
# docker push dimahkiin/cryptopro-extract:latest
# docker push dimahkiin/cryptopro-extract-service:${VERSION}
# docker push dimahkiin/cryptopro-extract-service:latest

echo "Done!"

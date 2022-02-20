FROM golang:1.17
WORKDIR /app
COPY . /app

ENV GOOS=linux

RUN DEBIAN_FRONTEND=noninteractive \
    apt update && \
    apt install -y protobuf-compiler && \
    GO111MODULE=on \
    go get google.golang.org/protobuf/cmd/protoc-gen-go@v1.27.1 \
    google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2.0 && \
    export PATH="$PATH:$(go env GOPATH)/bin" && \
    chmod +x ./generate.sh && \
    ./generate.sh && \
    go install ./...
CMD ["/bin/go/grpcgoonch"]
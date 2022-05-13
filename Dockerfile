FROM thaigoonch/sharkbuild:1.0 AS shark
WORKDIR /app
COPY . /app

ENV GOOS=linux

RUN ./generate.sh

FROM golang:1.17
COPY --from=shark /app /app
WORKDIR /app
RUN go install ./...

ENTRYPOINT ["/go/bin/restgoonch"]
EXPOSE 8080
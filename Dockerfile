FROM golang:1.18

COPY . $GOPATH/src/github.com/ennetech/beppe
WORKDIR $GOPATH/src/github.com/ennetech/beppe

RUN go get -d -v ./...
RUN go install -v ./...

ENTRYPOINT ["beppe"]
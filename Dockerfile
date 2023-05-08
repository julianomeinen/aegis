FROM golang:1.20

ENV GO111MODULE=on

WORKDIR /app

COPY app .

RUN go mod download

RUN go mod tidy

RUN go build -o main .

EXPOSE 8080

CMD ["./main"]

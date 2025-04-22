FROM golang:1.24-alpine as builder

WORKDIR /app
COPY . .
RUN go build -o /mtls-proxy ./cmd/proxy/

FROM alpine
COPY --from=builder /mtls-proxy /mtls-proxy
EXPOSE 8080
CMD ["/mtls-proxy"]

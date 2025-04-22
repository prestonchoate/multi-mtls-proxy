FROM golang:1.24-alpine as builder

WORKDIR /app
COPY . .
RUN go build -o /admin-api ./cmd/admin/

FROM alpine
COPY --from=builder /admin-api /admin-api
EXPOSE 8080
CMD ["/admin-api"]


FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -buildvcs=false -trimpath -o /server ./cmd/server

FROM alpine:3.22
RUN apk add --no-cache ca-certificates && addgroup -S app && adduser -S -G app app
COPY --from=build /server /usr/local/bin/server
USER app
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/server"]

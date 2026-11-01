# Gossiper, built from the repository root (the compose file sets the build context to ../..).
FROM golang:1.27.3-alpine3.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/gossiper ./cmd/gossiper

FROM alpine:3.24
RUN apk add --no-cache ca-certificates
COPY --from=build /out/gossiper /usr/local/bin/gossiper
EXPOSE 3000
ENTRYPOINT ["gossiper"]
CMD ["serve"]

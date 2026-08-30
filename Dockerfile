# Local/dev build. Releases use goreleaser + docker/Dockerfile-static.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-w -s -X github.com/getarcaneapp/apns-relay/internal/config.Version=${VERSION}" -o /out/apns-relay ./cmd

FROM gcr.io/distroless/static-debian13:nonroot
WORKDIR /app
COPY --from=build /out/apns-relay ./apns-relay
ENV RELAY_LISTEN_ADDR=:3554
ENV RELAY_DATABASE_PATH=/app/data/relay.db
EXPOSE 3554
VOLUME ["/app/data"]
ENTRYPOINT ["/app/apns-relay"]

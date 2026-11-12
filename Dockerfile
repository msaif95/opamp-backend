FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/opamp-backend ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/opamp-backend /opamp-backend
COPY migrations /migrations
ENV MIGRATIONS_DIR=/migrations
EXPOSE 4320 8080
ENTRYPOINT ["/opamp-backend"]

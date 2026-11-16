FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/opamp-backend ./cmd/server
# The command-line tool for every platform, offered for download from the console.
RUN for p in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64 windows_amd64; do \
      os=${p%_*}; arch=${p#*_}; ext=; [ "$os" = windows ] && ext=.exe; \
      CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/opampctl/opampctl_$p$ext ./cmd/opampctl || exit 1; \
    done

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/opamp-backend /opamp-backend
COPY migrations /migrations
COPY --from=build /out/opampctl /opampctl
ENV MIGRATIONS_DIR=/migrations OPAMPCTL_DIR=/opampctl
EXPOSE 4320 8080
# Numeric, so Kubernetes can verify runAsNonRoot.
USER 65532:65532
ENTRYPOINT ["/opamp-backend"]

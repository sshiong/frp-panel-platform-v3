FROM node:22-bookworm-slim AS client-ui
WORKDIR /src/web/client
COPY web/client/package.json web/client/package-lock.json ./
RUN npm ci --ignore-scripts
COPY web/client/ ./
RUN npm run build

FROM golang:1.25-bookworm AS client-build
WORKDIR /src/client
COPY client/go.mod client/go.sum ./
RUN go mod download
COPY client/ ./
COPY --from=client-ui /src/web/client/dist /src/client/internal/httpapi/static/generated
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/frp-panel-client ./cmd/client

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=client-build /out/frp-panel-client /app/frp-panel-client
USER nonroot:nonroot
EXPOSE 7410
ENTRYPOINT ["/app/frp-panel-client"]

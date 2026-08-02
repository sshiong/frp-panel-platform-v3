FROM node:22-bookworm-slim AS admin-ui
WORKDIR /src/web/admin
COPY web/admin/package.json web/admin/package-lock.json ./
RUN npm ci --ignore-scripts
COPY web/admin/ ./
RUN npm run build

FROM golang:1.25-bookworm AS server-build
WORKDIR /src/server
COPY server/go.mod server/go.sum ./
RUN go mod download
COPY server/ ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/frp-panel-server ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=server-build /out/frp-panel-server /app/frp-panel-server
COPY --from=admin-ui /src/web/admin/dist /app/web/admin/dist
ENV FRP_ADMIN_WEB_DIR=/app/web/admin/dist
USER nonroot:nonroot
EXPOSE 7400 7443
ENTRYPOINT ["/app/frp-panel-server"]

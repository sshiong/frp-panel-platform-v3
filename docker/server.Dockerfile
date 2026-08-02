FROM node:22-bookworm-slim AS admin-ui
WORKDIR /src
COPY contracts/generated/server-api.d.ts /src/contracts/generated/server-api.d.ts
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
COPY --from=admin-ui /src/web/admin/dist /src/server/internal/httpapi/static/generated
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/frp-panel-server ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=server-build /out/frp-panel-server /app/frp-panel-server
USER nonroot:nonroot
EXPOSE 7400 7443
ENTRYPOINT ["/app/frp-panel-server"]

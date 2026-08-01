# Fixed FRPS/FRPC network fixture

This fixture deliberately exercises only the native FRP transport path. It
does not claim Server Plugin authorization, Cloudflare, or ACME coverage.
The repository script starts fixed binaries, verifies both TOML files, and
probes the TCP proxy at `127.0.0.1:17080` while this directory is served on
`127.0.0.1:17081`.

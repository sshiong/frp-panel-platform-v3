# Troubleshooting

## Mapping is `pending_apply`

Check Client Panel `Local Runtime` for Supervisor state, `desired_config_version` vs `applied_config_version`, and the sanitized error. The Server keeps the port lease while the Client is offline or in `config_error`.

## Domain is `pending_dns`

This means the local binding and desired config are reserved, but the Cloudflare Provider has not completed DNS ownership/permission work. Configure and verify a Server-side Cloudflare Token; never paste it into the Client Panel.

## Client cannot connect to an IP

Production does not support skipped TLS verification. Use an IP SAN, a trusted CA, or the explicit fingerprint trust flow before entering a password.

export type CredentialSetupState = {
  must_change_password: boolean
  must_change_username: boolean
}

const USERNAME_PATTERN = /^[A-Za-z][A-Za-z0-9._-]{2,39}$/

export function isValidUsername(value: string): boolean {
  return USERNAME_PATTERN.test(value.trim())
}

export function isValidPassword(value: string): boolean {
  return value.length >= 12
}

export function requiresCredentialSetup(user: CredentialSetupState | null): boolean {
  return Boolean(user?.must_change_password || user?.must_change_username)
}

export function isDangerousAdminAction(action: string): boolean {
  return new Set(['create_user', 'disable_user', 'reset_password', 'reset_frp_credential', 'delete_user', 'force_delete_user', 'save_cloudflare_token', 'clear_cloudflare_token']).has(action)
}

import assert from 'node:assert/strict'
import test from 'node:test'
import { isDangerousAdminAction, isValidPassword, isValidUsername, requiresCredentialSetup } from '../src/policy.ts'

test('admin credential policy validates the documented boundaries', () => {
  assert.equal(isValidUsername('control-admin'), true)
  assert.equal(isValidUsername('ab'), false)
  assert.equal(isValidUsername('1-admin'), false)
  assert.equal(isValidUsername('admin name'), false)
  assert.equal(isValidPassword('short'), false)
  assert.equal(isValidPassword('long-enough-password'), true)
})

test('admin setup policy blocks the panel until first-login flags are cleared', () => {
  assert.equal(requiresCredentialSetup(null), false)
  assert.equal(requiresCredentialSetup({ must_change_password: true, must_change_username: false }), true)
  assert.equal(requiresCredentialSetup({ must_change_password: false, must_change_username: true }), true)
  assert.equal(requiresCredentialSetup({ must_change_password: false, must_change_username: false }), false)
})

test('admin destructive actions are explicitly re-authenticated', () => {
  assert.equal(isDangerousAdminAction('delete_user'), true)
  assert.equal(isDangerousAdminAction('clear_cloudflare_token'), true)
  assert.equal(isDangerousAdminAction('refresh_dashboard'), false)
})

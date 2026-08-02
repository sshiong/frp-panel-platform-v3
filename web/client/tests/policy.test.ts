import assert from 'node:assert/strict'
import test from 'node:test'
import { canCreateDomain, domainStatusClass, isDangerousClientAction, mappingStatusClass } from '../src/policy.ts'

test('client mapping statuses remain distinct at the UI boundary', () => {
  assert.equal(mappingStatusClass('running'), 'running')
  assert.equal(mappingStatusClass('config_error'), 'danger')
  assert.equal(mappingStatusClass('pending_apply'), 'pending')
  assert.equal(mappingStatusClass('offline'), 'offline')
})

test('client domain statuses retain pending and failure semantics', () => {
  assert.equal(domainStatusClass('active'), 'running')
  assert.equal(domainStatusClass('dns_error'), 'danger')
  assert.equal(domainStatusClass('pending_dns'), 'pending')
})

test('client dangerous actions and domain prerequisites are explicit', () => {
  assert.equal(isDangerousClientAction('delete_mapping'), true)
  assert.equal(isDangerousClientAction('overwrite_dns'), true)
  assert.equal(isDangerousClientAction('refresh'), false)
  assert.equal(canCreateDomain(1), true)
  assert.equal(canCreateDomain(0), false)
  assert.equal(canCreateDomain(1.5), false)
})

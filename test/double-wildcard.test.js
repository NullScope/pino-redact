'use strict'

const { test } = require('node:test')
const { strict: assert } = require('node:assert')
const slowRedact = require('../index.js')

test('** redacts field at top level', () => {
  const obj = { password: 'secret', name: 'john' }
  const redact = slowRedact({ paths: ['**.password'] })
  const result = JSON.parse(redact(obj))

  assert.strictEqual(result.password, '[REDACTED]')
  assert.strictEqual(result.name, 'john')
  assert.strictEqual(obj.password, 'secret') // original unchanged
})

test('** redacts field at nested level', () => {
  const obj = { user: { password: 'secret', name: 'john' } }
  const redact = slowRedact({ paths: ['**.password'] })
  const result = JSON.parse(redact(obj))

  assert.strictEqual(result.user.password, '[REDACTED]')
  assert.strictEqual(result.user.name, 'john')
  assert.strictEqual(obj.user.password, 'secret')
})

test('** redacts field at all depths simultaneously', () => {
  const obj = {
    password: 'top',
    user: {
      password: 'mid',
      profile: {
        password: 'deep',
      },
    },
  }
  const redact = slowRedact({ paths: ['**.password'] })
  const result = JSON.parse(redact(obj))

  assert.strictEqual(result.password, '[REDACTED]')
  assert.strictEqual(result.user.password, '[REDACTED]')
  assert.strictEqual(result.user.profile.password, '[REDACTED]')
  // originals unchanged
  assert.strictEqual(obj.password, 'top')
  assert.strictEqual(obj.user.password, 'mid')
  assert.strictEqual(obj.user.profile.password, 'deep')
})

test('** redacts field inside arrays at any depth', () => {
  const obj = {
    users: [
      { password: 'secret1' },
      { password: 'secret2', info: { password: 'nested-secret' } },
    ],
  }
  const redact = slowRedact({ paths: ['**.password'] })
  const result = JSON.parse(redact(obj))

  assert.strictEqual(result.users[0].password, '[REDACTED]')
  assert.strictEqual(result.users[1].password, '[REDACTED]')
  assert.strictEqual(result.users[1].info.password, '[REDACTED]')
})

test('** only redacts matching field, leaves others intact', () => {
  const obj = {
    a: { secret: 'keep', password: 'redact' },
    b: { nested: { secret: 'keep', password: 'redact' } },
  }
  const redact = slowRedact({ paths: ['**.password'] })
  const result = JSON.parse(redact(obj))

  assert.strictEqual(result.a.secret, 'keep')
  assert.strictEqual(result.a.password, '[REDACTED]')
  assert.strictEqual(result.b.nested.secret, 'keep')
  assert.strictEqual(result.b.nested.password, '[REDACTED]')
})

test('prefix.** redacts field only within prefix subtree', () => {
  const obj = {
    user: { password: 'redact', name: 'john' },
    session: { password: 'keep' },
  }
  const redact = slowRedact({ paths: ['user.**.password'] })
  const result = JSON.parse(redact(obj))

  assert.strictEqual(result.user.password, '[REDACTED]')
  assert.strictEqual(result.user.name, 'john')
  assert.strictEqual(result.session.password, 'keep')
})

test('prefix.** redacts at all depths within the prefix', () => {
  const obj = {
    user: {
      password: 'mid',
      auth: {
        password: 'deep',
      },
    },
    other: { password: 'untouched' },
  }
  const redact = slowRedact({ paths: ['user.**.password'] })
  const result = JSON.parse(redact(obj))

  assert.strictEqual(result.user.password, '[REDACTED]')
  assert.strictEqual(result.user.auth.password, '[REDACTED]')
  assert.strictEqual(result.other.password, 'untouched')
})

test('** with custom censor value', () => {
  const obj = { user: { token: 'abc', profile: { token: 'xyz' } } }
  const redact = slowRedact({ paths: ['**.token'], censor: '***' })
  const result = JSON.parse(redact(obj))

  assert.strictEqual(result.user.token, '***')
  assert.strictEqual(result.user.profile.token, '***')
})

test('** with censor function receives correct path', () => {
  const obj = {
    password: 'top',
    user: { password: 'nested' },
  }

  const calls = []
  const redact = slowRedact({
    paths: ['**.password'],
    censor: (value, path) => {
      calls.push({ value, path: [...path] })
      return '[REDACTED]'
    },
  })
  redact(obj)

  assert.strictEqual(calls.length, 2)
  const pathStrings = calls.map((c) => c.path.join('.'))
  assert.ok(pathStrings.includes('password'))
  assert.ok(pathStrings.includes('user.password'))
})

test('** with remove option deletes keys at all depths', () => {
  const obj = {
    password: 'top',
    user: { password: 'nested', name: 'john' },
  }
  const redact = slowRedact({ paths: ['**.password'], remove: true })
  const result = JSON.parse(redact(obj))

  assert.strictEqual('password' in result, false)
  assert.strictEqual('password' in result.user, false)
  assert.strictEqual(result.user.name, 'john')
})

test('** does not match field that does not exist', () => {
  const obj = { user: { name: 'john' } }
  const redact = slowRedact({ paths: ['**.password'] })
  const result = JSON.parse(redact(obj))

  assert.deepStrictEqual(result, obj)
})

test('** with serialize: false returns object and restore works', () => {
  const obj = { user: { password: 'secret', name: 'john' } }
  const redact = slowRedact({ paths: ['**.password'], serialize: false })
  const result = redact(obj)

  assert.strictEqual(result.user.password, '[REDACTED]')
  assert.strictEqual(result.user.name, 'john')

  const restored = result.restore()
  assert.strictEqual(restored.user.password, 'secret')
})

test('** on multi-level path: **.secret.key', () => {
  const obj = {
    secret: { key: 'top' },
    a: { secret: { key: 'mid' } },
    b: { c: { secret: { key: 'deep' } } },
  }
  const redact = slowRedact({ paths: ['**.secret.key'] })
  const result = JSON.parse(redact(obj))

  assert.strictEqual(result.secret.key, '[REDACTED]')
  assert.strictEqual(result.a.secret.key, '[REDACTED]')
  assert.strictEqual(result.b.c.secret.key, '[REDACTED]')
})

test('** at end redacts all own keys of the target', () => {
  const obj = { user: { name: 'john', password: 'secret', token: 'abc' } }
  const redact = slowRedact({ paths: ['user.**'] })
  const result = JSON.parse(redact(obj))

  assert.strictEqual(result.user.name, '[REDACTED]')
  assert.strictEqual(result.user.password, '[REDACTED]')
  assert.strictEqual(result.user.token, '[REDACTED]')
})

test('**.credentials.*.password redacts password inside each child of a deeply-found key', () => {
  const obj = {
    credentials: {
      password: 'top-secret',
      admin: { password: 'password', name: 'alice' },
      user: { password: 'password', name: 'bob' },
    },
    service: {
      password: 'service-secret',
      credentials: {
        api: { password: 'password', name: 'svc' },
      },
    },
  }

  const redact = slowRedact({ paths: ['**.credentials.*.password'] })
  const result = JSON.parse(redact(obj))

  assert.strictEqual(result.credentials.password, 'top-secret')
  assert.strictEqual(result.credentials.admin.password, '[REDACTED]')
  assert.strictEqual(result.credentials.user.password, '[REDACTED]')
  assert.strictEqual(result.credentials.admin.name, 'alice')
  assert.strictEqual(result.service.password, 'service-secret')
  assert.strictEqual(result.service.credentials.api.password, '[REDACTED]')
  assert.strictEqual(result.service.credentials.api.name, 'svc')
})

test('** combined with another path in same redact instance', () => {
  const obj = {
    password: 'secret',
    user: { token: 'abc', password: 'nested' },
  }
  const redact = slowRedact({ paths: ['**.password', 'user.token'] })
  const result = JSON.parse(redact(obj))

  assert.strictEqual(result.password, '[REDACTED]')
  assert.strictEqual(result.user.password, '[REDACTED]')
  assert.strictEqual(result.user.token, '[REDACTED]')
})

test('**.items[*].password redacts password in every element of any items array at any depth', () => {
  const obj = {
    items: [
      { password: 'password', name: 'john' },
      { password: 'password', name: 'jane' },
    ],
    section: {
      items: [{ password: 'password', name: 'alice' }],
    },
    other: { password: 'untouched' },
  }

  const redact = slowRedact({ paths: ['**.items[*].password'] })
  const result = JSON.parse(redact(obj))

  assert.strictEqual(result.items[0].password, '[REDACTED]')
  assert.strictEqual(result.items[0].name, 'john')
  assert.strictEqual(result.items[1].password, '[REDACTED]')
  assert.strictEqual(result.section.items[0].password, '[REDACTED]')
  assert.strictEqual(result.section.items[0].name, 'alice')
  assert.strictEqual(result.other.password, 'untouched')
})

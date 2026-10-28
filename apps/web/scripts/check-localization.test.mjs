import { test } from 'node:test'
import assert from 'node:assert/strict'
import { untranslatedWords } from './check-localization.mjs'

test('detects untranslated copy even next to a Chinese heading', () => {
  assert.deepEqual(untranslatedWords('规则策略 Refresh policies'), ['Refresh', 'policies'])
  assert.deepEqual(untranslatedWords('direct'), ['direct'])
  assert.deepEqual(untranslatedWords('Readback pending'), ['Readback', 'pending'])
})
test('allows technical identifiers but not English UI sentences', () => {
  assert.deepEqual(untranslatedWords('IPv4 与 IPv6 · TCP / UDP · OPNsense'), [])
  assert.deepEqual(untranslatedWords('能力 provider.publish_hot 尚未启用'), [])
  assert.deepEqual(untranslatedWords('https://gateway.example.test:8443'), [])
  assert.deepEqual(untranslatedWords('请输入设备名称。'), [])
})

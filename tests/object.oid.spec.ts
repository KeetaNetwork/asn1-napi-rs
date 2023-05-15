import test from 'ava'

import * as lib from '../index'

const TEST_OIDS: lib.ASN1OID[] = [
  { type: 'oid', oid: 'sha256' },
  { type: 'oid', oid: 'commonName' },
  { type: 'oid', oid: '1.2.3.4' },
]

const TEST_OIDS_ASN1 = [
  new Uint8Array([
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
  ]).buffer,
  new Uint8Array([0x06, 0x03, 0x55, 0x04, 0x03]).buffer,
  new Uint8Array([0x06, 0x03, 0x2a, 0x03, 0x04]).buffer,
]

test('JS ASN1OID to ASN1 conversion', (t) => {
  TEST_OIDS.forEach((v, i) => {
    t.deepEqual(lib.JStoASN1(v).toBER(), TEST_OIDS_ASN1[i])
  })
})

test('ASN1 to Js ASN1OID conversion from byte code', (t) => {
  TEST_OIDS_ASN1.forEach((v, i) => {
    const data = new Uint8Array(v)
    const obj = new lib.ASN1Decoder(Array.from(data))

    t.deepEqual(obj.intoOid(), TEST_OIDS[i])
    t.deepEqual(lib.ASN1toJS(v), TEST_OIDS[i])
  })
})

test('ASN1 to Js ASN1OID conversion from base64', (t) => {
  const oid: lib.ASN1OID = { type: 'oid', oid: 'sha256' }
  const obj = lib.ASN1Decoder.fromBase64('BglghkgBZQMEAgE=')

  t.deepEqual(obj.intoOid(), oid)
})

test('ASN1 to Js ASN1OID conversion round trip', (t) => {
  TEST_OIDS_ASN1.forEach((v, i) => {
    const js = new lib.ASN1Decoder(v)

    t.deepEqual(js.intoOid(), TEST_OIDS[i])
    t.deepEqual(lib.JStoASN1(lib.ASN1toJS(v)).toBER(), TEST_OIDS_ASN1[i])
  })
})

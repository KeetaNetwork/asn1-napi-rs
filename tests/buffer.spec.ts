import test from 'ava'

import * as lib from '../index'

const TEST_BUFFERS = [Buffer.from(new Uint8Array([1, 2, 3, 4, 5]))]

const TEST_BUFFERS_ASN1 = [
  new Uint8Array([0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]).buffer,
]

test('JS Buffer to ASN1 conversion', (t) => {
  TEST_BUFFERS.forEach((v, i) => {
    t.deepEqual(lib.JStoASN1(v).toBER(), TEST_BUFFERS_ASN1[i])
  })
})

test('ASN1 to Js Buffer conversion from byte code', (t) => {
  TEST_BUFFERS_ASN1.forEach((v, i) => {
    const data = new Uint8Array(v)
    const obj = new lib.ASN1Decoder(Array.from(data))

    t.deepEqual(obj.intoBuffer(), TEST_BUFFERS[i])
    t.deepEqual(lib.ASN1toJS(v), TEST_BUFFERS[i])
  })
})

test('ASN1 to Js Buffer conversion from base64', (t) => {
  const obj = lib.ASN1Decoder.fromBase64('BAUBAgMEBQ==')

  t.deepEqual(obj.intoBuffer(), Buffer.from(new Uint8Array([1, 2, 3, 4, 5])))
})

test('ASN1 to Js Buffer conversion round trip', (t) => {
  TEST_BUFFERS_ASN1.forEach((v, i) => {
    const js = new lib.ASN1Decoder(v)

    t.deepEqual(js.intoBuffer(), TEST_BUFFERS[i])
    t.deepEqual(lib.JStoASN1(lib.ASN1toJS(v)).toBER(), TEST_BUFFERS_ASN1[i])
  })
})

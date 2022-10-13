import test from 'ava'

import * as lib from '../index'

const TEST_BITSTRINGS: lib.ASN1BitString[] = [
  {
    type: 'bitstring',
    value: Buffer.from(
      'xbjd90jjB56hh4ZJNd24wupOqpzfBq/ig+21XWs4SbQ=',
      'base64',
    ),
  },
]

const TEST_BITSTRINGS_ASN1 = [
  new Uint8Array([
    0x03, 0x21, 0x00, 0xc5, 0xb8, 0xdd, 0xf7, 0x48, 0xe3, 0x07, 0x9e, 0xa1,
    0x87, 0x86, 0x49, 0x35, 0xdd, 0xb8, 0xc2, 0xea, 0x4e, 0xaa, 0x9c, 0xdf,
    0x06, 0xaf, 0xe2, 0x83, 0xed, 0xb5, 0x5d, 0x6b, 0x38, 0x49, 0xb4,
  ]).buffer,
]

test('JS ASN1BitString to ASN1 conversion', (t) => {
  TEST_BITSTRINGS.map((v, i) => {
    t.deepEqual(lib.JStoASN1(v).toBER(), TEST_BITSTRINGS_ASN1[i])
  })
})

test('ASN1 to Js ASN1BitString conversion from byte code', (t) => {
  TEST_BITSTRINGS_ASN1.map((v, i) => {
    const data = new Uint8Array(v)
    const obj = new lib.ASN1Decoder(Array.from(data))

    t.deepEqual(obj.intoBitString(), TEST_BITSTRINGS[i])
    t.deepEqual(lib.ASN1toJS(v), TEST_BITSTRINGS[i])
  })
})

test('ASN1 to ASN1BitString conversion from base64', (t) => {
  const obj = lib.ASN1Decoder.fromBase64('AwYAChAUIAk=')

  t.deepEqual(obj.intoBitString(), {
    type: 'bitstring',
    value: Buffer.from(new Uint8Array([0xa, 0x10, 20, 32, 9])),
  })
})

test('ASN1 to Js ASN1BitString conversion round trip', (t) => {
  TEST_BITSTRINGS_ASN1.map((v, i) => {
    const js = new lib.ASN1Decoder(v)

    t.deepEqual(js.intoBitString(), TEST_BITSTRINGS[i])
    t.deepEqual(lib.JStoASN1(lib.ASN1toJS(v)).toBER(), TEST_BITSTRINGS_ASN1[i])
  })
})

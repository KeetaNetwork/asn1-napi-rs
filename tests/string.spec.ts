import test from 'ava'

import * as lib from '../index'

const TEST_STRINGS = ['test', 'This is a Test String!\uD83D\uDE03']

const TEST_STRINGS_ASN1 = [
  new Uint8Array([0x13, 0x4, 0x74, 0x65, 0x73, 0x74]).buffer,
  new Uint8Array([
    0x13, 0x1a, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20,
    0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x21,
    0xf0, 0x9f, 0x98, 0x83,
  ]).buffer,
  // UTF-16
  // [
  //   0x13, 0x18, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61,
  //   0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67,
  //   0x21, 0x3d, 0x03,
  // ],
]

test('JS string to ASN1 conversion', (t) => {
  TEST_STRINGS.map((v, i) => {
    t.deepEqual(lib.JStoASN1(v).toBER(), TEST_STRINGS_ASN1[i])
  })
})

test('ASN1 to Js string conversion from byte code', (t) => {
  TEST_STRINGS_ASN1.map((v, i) => {
    const obj = new lib.ASN1Decoder(v)

    t.deepEqual(obj.intoString(), TEST_STRINGS[i])
    t.deepEqual(lib.ASN1toJS(v), TEST_STRINGS[i])
  })
})

test('ASN1 to Js string conversion from base64', (t) => {
  const obj = lib.ASN1Decoder.fromBase64('EwR0ZXN0')

  t.deepEqual(obj.intoString(), 'test')
})

test('ASN1 to Js string conversion round trip', (t) => {
  TEST_STRINGS_ASN1.map((v, i) => {
    const data = new Uint8Array(v)
    const js = new lib.ASN1Decoder(Array.from(data))

    t.deepEqual(js.intoString(), TEST_STRINGS[i])
    t.deepEqual(lib.JStoASN1(lib.ASN1toJS(v)).toBER(), TEST_STRINGS_ASN1[i])
  })
})

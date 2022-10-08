import test from 'ava'

import * as lib from '../index'

const TEST_BOOLEAN = [true, false]

const TEST_BOOLEAN_ASN1 = [
  new Uint8Array([0x1, 0x1, 0xff]).buffer,
  new Uint8Array([0x1, 0x1, 0x0]).buffer,
]

test('JS boolean to ASN1 conversion', (t) => {
  TEST_BOOLEAN.map((v, i) => {
    t.deepEqual(lib.JStoASN1(v).toBER(), TEST_BOOLEAN_ASN1[i])
  })
})

test('ASN1 to Js boolean conversion from byte code', (t) => {
  TEST_BOOLEAN_ASN1.map((v, i) => {
    const obj = new lib.Asn1(v)

    t.deepEqual(obj.intoBool(), TEST_BOOLEAN[i])
    t.deepEqual(lib.ASN1toJS(v), TEST_BOOLEAN[i])
  })
})

test('ASN1 to JS boolean conversion from base64', (t) => {
  const obj_true = lib.Asn1.fromBase64('AQH/')
  const obj_false = lib.Asn1.fromBase64('AQEA')

  t.deepEqual(obj_true.intoBool(), true)
  t.deepEqual(obj_false.intoBool(), false)
})

test('ASN1 to Js boolean conversion round trip', (t) => {
  TEST_BOOLEAN_ASN1.map((v, i) => {
    const data = new Uint8Array(v)
    const js = new lib.Asn1(Array.from(data))

    t.deepEqual(js.intoBool(), TEST_BOOLEAN[i])
    t.deepEqual(lib.JStoASN1(lib.ASN1toJS(v)).toBER(), TEST_BOOLEAN_ASN1[i])
  })
})

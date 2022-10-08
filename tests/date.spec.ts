import test from 'ava'

import * as lib from '../index'

const TEST_DATES = [new Date(0), new Date('2022-09-26T10:00:00.000+00:00')]

const TEST_DATES_ASN1 = [
  new Uint8Array([
    0x18, 0x13, 0x31, 0x39, 0x37, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x2e, 0x30, 0x30, 0x30, 0x5a,
  ]).buffer,
  new Uint8Array([
    0x18, 0x13, 0x32, 0x30, 0x32, 0x32, 0x30, 0x39, 0x32, 0x36, 0x31, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x2e, 0x30, 0x30, 0x30, 0x5a,
  ]).buffer,
]

test('JS Date to ASN1 conversion', (t) => {
  TEST_DATES.map((v, i) => {
    t.deepEqual(lib.JStoASN1(v).toBER(), TEST_DATES_ASN1[i])
  })
})

test('ASN1 to Js Date conversion from byte code', (t) => {
  TEST_DATES_ASN1.map((v, i) => {
    const obj = new lib.Asn1(v)

    t.deepEqual(obj.intoDate(), TEST_DATES[i])
    t.deepEqual(lib.ASN1toJS(v), TEST_DATES[i])
  })
})

test('ASN1 to Js Date conversion from base64', (t) => {
  const obj = lib.Asn1.fromBase64('GA8yMDIyMDkyNjEwMDAwMFo=')
  const date = obj.intoDate()

  t.true(date instanceof Date)
  t.deepEqual(date, new Date('2022-09-26T10:00:00.000+00:00'))
})

test('ASN1 to Js Date conversion round trip', (t) => {
  TEST_DATES_ASN1.map((v, i) => {
    const js = new lib.Asn1(v)

    t.deepEqual(js.intoDate(), TEST_DATES[i])
    t.deepEqual(lib.JStoASN1(lib.ASN1toJS(v)).toBER(), TEST_DATES_ASN1[i])
  })
})

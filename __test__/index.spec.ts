import test from 'ava'

import * as lib from '../index'

const TEST_INTEGERS = [0x00, 0x2a, 0x7f, 0x80, -0xffff]
const TEST_INTEGERS_ASN1 = [
  [0x02, 0x01, 0x00],
  [0x02, 0x01, 0x2a],
  [0x02, 0x01, 0x7f],
  [0x02, 0x02, 0x00, 0x80],
  [0x02, 0x03, 0xff, 0x00, 0x01],
]

const TEST_BIG_INTEGERS = [
  0x10203040506070809n,
  -0x10203040506070809n,
  //0xd164be58602b598abf3e63d5503cc991598065832610344d74c2a47d27906bc4n,
]
const TEST_BIG_INTEGERS_ASN1 = [
  [0x02, 0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
  [0x02, 0x09, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf7],
  // [
  //   0x02, 0x21, 0x00, 0xd1, 0x64, 0xbe, 0x58, 0x60, 0x2b, 0x59, 0x8a, 0xbf, 0x3e, 0x63, 0xd5, 0x50, 0x3c, 0xc9, 0x91,
  //   0x59, 0x80, 0x65, 0x83, 0x26, 0x10, 0x34, 0x4d, 0x74, 0xc2, 0xa4, 0x7d, 0x27, 0x90, 0x6b, 0xc4,
  // ],
]

test('JS boolean to ASN1 conversion', (t) => {
  t.deepEqual(lib.JStoASN1(true), [0x1, 0x1, 0xff])
  t.deepEqual(lib.JStoASN1(false), [0x1, 0x1, 0x0])
})

test('JS integer to ASN1 conversion', (t) => {
  TEST_INTEGERS.map((v, i) => {
    t.deepEqual(lib.JStoASN1(v), TEST_INTEGERS_ASN1[i])
  })
})

test('JS BigInt to ASN1 conversion', (t) => {
  TEST_BIG_INTEGERS.map((v, i) => {
    t.deepEqual(lib.JStoASN1(v), TEST_BIG_INTEGERS_ASN1[i])
  })
})

test('JS string to ASN1 conversion', (t) => {
  t.deepEqual(lib.JStoASN1('test'), [0x13, 0x4, 0x74, 0x65, 0x73, 0x74])
})

test('JS Buffer to ASN1 conversion', (t) => {
  t.deepEqual(lib.JStoASN1(Buffer.from(new Uint8Array([1, 2, 3, 4, 5]))), [0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05])
})

test('JS ANS1OID to ASN1 conversion', (t) => {
  const oid: lib.ASN1OID = { type: 'oid', oid: 'sha256' }
  t.deepEqual(lib.JStoASN1(oid), [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])
})

test('JS Date to ASN1 conversion', (t) => {
  t.deepEqual(
    lib.JStoASN1(new Date('2022-09-26T10:00:00.000+00:00')),
    [0x18, 0xf, 0x32, 0x30, 0x32, 0x32, 0x30, 0x39, 0x32, 0x36, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a],
  )
})

test('ASN1 to JS boolean conversion from byte code', (t) => {
  const obj_true = new lib.Asn1([0x1, 0x1, 0xff])
  const obj_false = new lib.Asn1([0x1, 0x1, 0x0])

  t.deepEqual(obj_true.intoBool(), true)
  t.deepEqual(obj_false.intoBool(), false)
})

test('ASN1 to JS boolean conversion from base64', (t) => {
  const obj_true = lib.Asn1.fromBase64('AQH/')
  const obj_false = lib.Asn1.fromBase64('AQEA')

  t.deepEqual(obj_true.intoBool(), true)
  t.deepEqual(obj_false.intoBool(), false)
})

test('ASN1 to Js boolean conversion round trip', (t) => {
  const input_true = true
  const input_false = false
  const asn1_true = lib.JStoASN1(input_true)
  const asn1_false = lib.JStoASN1(input_false)
  const js_true = new lib.Asn1(asn1_true)
  const js_false = new lib.Asn1(asn1_false)

  t.deepEqual(js_true.intoBool(), input_true)
  t.deepEqual(js_false.intoBool(), input_false)
})

test('ASN1 to Js integer conversion from byte code', (t) => {
  const obj = new lib.Asn1([0x02, 0x01, 0x2a])

  t.deepEqual(obj.intoInteger(), 42)
})

test('ASN1 to Js integer conversion from base64', (t) => {
  const obj = lib.Asn1.fromBase64('AgEq')

  t.deepEqual(obj.intoInteger(), 42)
})

test('ASN1 to Js integer conversion round trip', (t) => {
  TEST_INTEGERS.map((v) => {
    t.deepEqual(lib.ASN1toJS(lib.JStoASN1(v)), v)
  })
})

test('ASN1 to Js BigInt conversion from byte code', (t) => {
  const result = BigInt('18591708106338011145')
  const asn1 = [0x02, 0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]
  const obj = new lib.Asn1(asn1)

  t.deepEqual(obj.intoBigInteger(), result)
  t.deepEqual(lib.ASN1toJS(asn1), result)
})

test('ASN1 to Js BigInt conversion from base64', (t) => {
  const result = BigInt('18591708106338011145')
  const base64 = 'AgkBAgMEBQYHCAk='
  const obj = lib.Asn1.fromBase64(base64)

  t.deepEqual(obj.intoBigInteger(), result)
  t.deepEqual(lib.ASN1toJS(base64), result)
})

test('ASN1 to Js BigInt conversion round trip', (t) => {
  const input = BigInt('18591708106338011145')
  const asn1 = lib.JStoASN1(input)
  const js = new lib.Asn1(asn1)

  t.deepEqual(js.intoBigInteger(), input)
  t.deepEqual(lib.ASN1toJS(lib.JStoASN1(input)), input)
})

test('ASN1 to Js string conversion from byte code', (t) => {
  const obj = new lib.Asn1([0x13, 0x4, 0x74, 0x65, 0x73, 0x74])

  t.deepEqual(obj.intoString(), 'test')
})

test('ASN1 to Js string conversion from base64', (t) => {
  const obj = lib.Asn1.fromBase64('EwR0ZXN0')

  t.deepEqual(obj.intoString(), 'test')
})

test('ASN1 to Js string conversion round trip', (t) => {
  const input = 'test'
  const asn1 = lib.JStoASN1(input)
  const js = new lib.Asn1(asn1)

  t.deepEqual(js.intoString(), input)
})

test('ASN1 to Js Date conversion from byte code', (t) => {
  const obj = new lib.Asn1([
    0x18, 0xf, 0x32, 0x30, 0x32, 0x32, 0x30, 0x39, 0x32, 0x36, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
  ])

  t.deepEqual(obj.intoDate(), new Date('2022-09-26T10:00:00.000+00:00'))
})

test('ASN1 to Js Date conversion from base64', (t) => {
  const obj = lib.Asn1.fromBase64('GA8yMDIyMDkyNjEwMDAwMFo=')

  t.deepEqual(obj.intoDate(), new Date('2022-09-26T10:00:00.000+00:00'))
})

test('ASN1 to Js Date conversion round trip', (t) => {
  const input = new Date('2022-09-26T10:00:00.000+00:00')
  const asn1 = lib.JStoASN1(input)
  const js = new lib.Asn1(asn1)

  t.deepEqual(js.intoDate(), input)
})

test('ASN1 to Js Buffer conversion from byte code', (t) => {
  const obj = new lib.Asn1([0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05])

  t.deepEqual(obj.intoBuffer(), Buffer.from(new Uint8Array([1, 2, 3, 4, 5])))
})

test('ASN1 to Js Buffer conversion from base64', (t) => {
  const obj = lib.Asn1.fromBase64('BAUBAgMEBQ==')

  t.deepEqual(obj.intoBuffer(), Buffer.from(new Uint8Array([1, 2, 3, 4, 5])))
})

test('ASN1 to Js Buffer conversion round trip', (t) => {
  const input = Buffer.from(new Uint8Array([1, 2, 3, 4, 5]))
  const asn1 = lib.JStoASN1(input)
  const js = new lib.Asn1(asn1)

  t.deepEqual(js.intoBuffer(), input)
})

test('ASN1 to Js ASN1OID conversion from byte code', (t) => {
  const oid: lib.ASN1OID = { type: 'oid', oid: 'sha256' }
  const obj = new lib.Asn1([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])

  t.deepEqual(obj.intoOid(), oid)
})

test('ASN1 to Js ASN1OID conversion from base64', (t) => {
  const oid: lib.ASN1OID = { type: 'oid', oid: 'sha256' }
  const obj = lib.Asn1.fromBase64('BglghkgBZQMEAgE=')

  t.deepEqual(obj.intoOid(), oid)
})

test('ASN1 to Js ASN1OID conversion round trip', (t) => {
  const input: lib.ASN1OID = { type: 'oid', oid: 'sha256' }
  const asn1 = lib.JStoASN1(input)
  const js = new lib.Asn1(asn1)

  t.deepEqual(js.intoOid(), input)
})

test('JS integer to BigInt conversion helper', (t) => {
  t.deepEqual(lib.ASN1IntegerToBigInt(42), BigInt('42'))
})

test('JS BigInt to Buffer conversion helper', (t) => {
  const input = BigInt('18591708106338011145')
  const buffer = lib.ASN1BigIntToBuffer(input)

  t.deepEqual(BigInt(`0x${buffer.subarray(0, buffer.length).toString('hex')}`), input)
})

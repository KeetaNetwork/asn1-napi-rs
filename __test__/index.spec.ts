import test from 'ava'

import * as lib from '../index'

test('JS boolean to ASN1 conversion', (t) => {
  t.deepEqual(lib.JStoASN1(true), [0x1, 0x1, 0xff])
  t.deepEqual(lib.JStoASN1(false), [0x1, 0x1, 0x0])
  t.deepEqual(lib.JStoASN1(42), [0x02, 0x01, 0x2a])
})

test('JS integer to ASN1 conversion', (t) => {
  t.deepEqual(lib.JStoASN1(42), [0x02, 0x01, 0x2a])
})

test('JS BigInt to ASN1 conversion', (t) => {
  t.deepEqual(
    lib.JStoASN1(BigInt('18591708106338011145')),
    [0x02, 0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
  )
})

test('JS string to ASN1 conversion', (t) => {
  t.deepEqual(lib.JStoASN1('test'), [0x13, 0x4, 0x74, 0x65, 0x73, 0x74])
})

test('JS Buffer to ASN1 conversion', (t) => {
  t.deepEqual(lib.JStoASN1(Buffer.from(new Uint8Array([1, 2, 3, 4, 5]))), [0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05])
})

// test('JS Date to ASN1 conversion', (t) => {
//   // eslint-disable-next-line no-console
//   const fixture = lib.JStoASN1(new Date('2022-09-26T10:00:00.000+00:00'))
//   const obj = new lib.Asn1(fixture)
//   // eslint-disable-next-line no-console
//   console.log(obj.intoDate())
//   t.deepEqual(
//     fixture,
//     [0x18, 0xf, 0x32, 0x30, 0x32, 0x32, 0x30, 0x39, 0x32, 0x36, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a],
//   )
// })

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
  const input = 42
  const asn1 = lib.JStoASN1(input)
  const js = new lib.Asn1(asn1)

  t.deepEqual(js.intoInteger(), input)
})

test('ASN1 to Js BigInt conversion from byte code', (t) => {
  const obj = new lib.Asn1([0x02, 0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09])

  t.deepEqual(obj.intoBigInteger(), BigInt('18591708106338011145'))
})

test('ASN1 to Js BigInt conversion from base64', (t) => {
  const obj = lib.Asn1.fromBase64('AgkBAgMEBQYHCAk=')

  t.deepEqual(obj.intoBigInteger(), BigInt('18591708106338011145'))
})

test('ASN1 to Js BigInt conversion round trip', (t) => {
  const input = BigInt('18591708106338011145')
  const asn1 = lib.JStoASN1(input)
  const js = new lib.Asn1(asn1)

  t.deepEqual(js.intoBigInteger(), input)
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

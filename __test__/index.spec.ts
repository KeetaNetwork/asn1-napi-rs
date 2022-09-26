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

test('JS string to ASN1 conversion', (t) => {
  t.deepEqual(lib.JStoASN1('test'), [0x13, 0x4, 0x74, 0x65, 0x73, 0x74])
})

// TODO
// test('JS Date to ASN1 conversion', (t) => {
//   // eslint-disable-next-line no-console
//   const fixture = lib.JStoASN1(new Date('2022-09-26T10:00:00.000+00:00'))
//   const obj = new lib.Asn1ToJs(fixture)
//   // eslint-disable-next-line no-console
//   console.log(obj.intoDate())
//   t.deepEqual(
//     fixture,
//     [0x18, 0xf, 0x32, 0x30, 0x32, 0x32, 0x30, 0x39, 0x32, 0x36, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a],
//   )
// })

test('ASN1 to JS boolean conversion from byte code', (t) => {
  const obj_true = new lib.Asn1ToJs([0x1, 0x1, 0xff])
  const obj_false = new lib.Asn1ToJs([0x1, 0x1, 0x0])

  t.deepEqual(obj_true.intoBool(), true)
  t.deepEqual(obj_false.intoBool(), false)
})

test('ASN1 to JS boolean conversion from base64', (t) => {
  const obj_true = lib.Asn1ToJs.fromBase64('AQH/')
  const obj_false = lib.Asn1ToJs.fromBase64('AQEA')

  t.deepEqual(obj_true.intoBool(), true)
  t.deepEqual(obj_false.intoBool(), false)
})

test('ASN1 to Js integer conversion from byte code', (t) => {
  const obj = new lib.Asn1ToJs([0x02, 0x01, 0x2a])

  t.deepEqual(obj.intoInteger(), 42)
})

test('ASN1 to Js integer conversion from base64', (t) => {
  const obj = lib.Asn1ToJs.fromBase64('AgEq')

  t.deepEqual(obj.intoInteger(), 42)
})

test('ASN1 to Js string conversion from byte code', (t) => {
  const obj = new lib.Asn1ToJs([0x13, 0x4, 0x74, 0x65, 0x73, 0x74])

  t.deepEqual(obj.intoString(), 'test')
})

test('ASN1 to Js string conversion from base64', (t) => {
  const obj = lib.Asn1ToJs.fromBase64('EwR0ZXN0')

  t.deepEqual(obj.intoString(), 'test')
})

test('ASN1 to Js Date conversion from byte code', (t) => {
  const obj = new lib.Asn1ToJs([
    0x18, 0xf, 0x32, 0x30, 0x32, 0x32, 0x30, 0x39, 0x32, 0x36, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
  ])

  t.deepEqual(obj.intoDate(), new Date('2022-09-26T10:00:00.000+00:00'))
})

test('ASN1 to Js Date conversion from base64', (t) => {
  const obj = lib.Asn1ToJs.fromBase64('GA8yMDIyMDkyNjEwMDAwMFo=')

  t.deepEqual(obj.intoDate(), new Date('2022-09-26T10:00:00.000+00:00'))
})

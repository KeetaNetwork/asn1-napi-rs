import test from 'ava'

import * as lib from '../index'

const TEST_INTEGERS = [0x00, 0x2a, 0x7f, 0x80, -0xffff]
const TEST_INTEGERS_ASN1 = [
  new Uint8Array([0x02, 0x01, 0x00]).buffer,
  new Uint8Array([0x02, 0x01, 0x2a]).buffer,
  new Uint8Array([0x02, 0x01, 0x7f]).buffer,
  new Uint8Array([0x02, 0x02, 0x00, 0x80]).buffer,
  new Uint8Array([0x02, 0x03, 0xff, 0x00, 0x01]).buffer,
]

const TEST_BIG_INTEGERS = [
  0n,
  0x7fn,
  0x80n,
  0x10203040506070809n,
  -0x10203040506070809n,
  0xd164be58602b598abf3e63d5503cc991598065832610344d74c2a47d27906bc4n,
  0xeba6dad102b4ef356bb21624385ddc39a5bad53d5c927f50ca6792044fb213b1093c39eb37a839e0ac416808d1545953de265ee2a4ed41f5d1a02921a02833aan,
]
const TEST_BIG_INTEGERS_ASN1 = [
  new Uint8Array([0x02, 0x01, 0x00]).buffer,
  new Uint8Array([0x02, 0x01, 0x7f]).buffer,
  new Uint8Array([0x02, 0x02, 0x00, 0x80]).buffer,
  new Uint8Array([
    0x02, 0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
  ]).buffer,
  new Uint8Array([
    0x02, 0x09, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf7,
  ]).buffer,
  new Uint8Array([
    0x02, 0x21, 0x00, 0xd1, 0x64, 0xbe, 0x58, 0x60, 0x2b, 0x59, 0x8a, 0xbf,
    0x3e, 0x63, 0xd5, 0x50, 0x3c, 0xc9, 0x91, 0x59, 0x80, 0x65, 0x83, 0x26,
    0x10, 0x34, 0x4d, 0x74, 0xc2, 0xa4, 0x7d, 0x27, 0x90, 0x6b, 0xc4,
  ]).buffer,
  new Uint8Array([
    0x02, 0x41, 0x00, 0xeb, 0xa6, 0xda, 0xd1, 0x02, 0xb4, 0xef, 0x35, 0x6b,
    0xb2, 0x16, 0x24, 0x38, 0x5d, 0xdc, 0x39, 0xa5, 0xba, 0xd5, 0x3d, 0x5c,
    0x92, 0x7f, 0x50, 0xca, 0x67, 0x92, 0x04, 0x4f, 0xb2, 0x13, 0xb1, 0x09,
    0x3c, 0x39, 0xeb, 0x37, 0xa8, 0x39, 0xe0, 0xac, 0x41, 0x68, 0x08, 0xd1,
    0x54, 0x59, 0x53, 0xde, 0x26, 0x5e, 0xe2, 0xa4, 0xed, 0x41, 0xf5, 0xd1,
    0xa0, 0x29, 0x21, 0xa0, 0x28, 0x33, 0xaa,
  ]).buffer,
]

function NodeASN1BigIntToBuffer(value: bigint | bigint): Buffer {
  /**
   * Convert value to Hex
   */
  let valueStr = value.toString(16)

  /**
   * Determine if the value is negative
   */
  let isNegative = false
  if (valueStr[0] === '-') {
    isNegative = true
    valueStr = valueStr.slice(1)
  }

  /*
   * Ensure there are an even number of hex digits
   */
  if (valueStr.length % 2 !== 0) {
    valueStr = '0' + valueStr
  }

  /*
   * Pad with a leading 0 byte if the MSB is 1 to avoid writing a
   * negative number
   */
  const leader = valueStr.slice(0, 2)
  const leaderValue = Number(`0x${leader}`)
  if (!isNegative) {
    if (leaderValue > 127) {
      valueStr = '00' + valueStr
    }
  } else {
    if (leaderValue <= 127) {
      valueStr = 'FF' + valueStr
    }
  }

  /*
   * Convert to a buffer
   */
  const valueBuffer = Buffer.from(valueStr, 'hex')
  return valueBuffer
}

test('JS number to ASN1 conversion', (t) => {
  TEST_INTEGERS.forEach((v, i) => {
    t.deepEqual(lib.JStoASN1(v).toBER(), TEST_INTEGERS_ASN1[i])
  })
})

test('ASN1 to Js number conversion from byte code', (t) => {
  TEST_INTEGERS_ASN1.forEach((v, i) => {
    const obj = new lib.ASN1Decoder(v)

    t.deepEqual(obj.intoInteger(), TEST_INTEGERS[i])
    t.deepEqual(lib.ASN1toJS(v), BigInt(TEST_INTEGERS[i]))
  })
})

test('ASN1 to Js number conversion from base64', (t) => {
  const obj = lib.ASN1Decoder.fromBase64('AgEq')

  t.deepEqual(obj.intoInteger(), 42)
})

test('ASN1 to Js number conversion round trip', (t) => {
  TEST_INTEGERS.forEach((v) => {
    t.deepEqual(lib.ASN1toJS(lib.JStoASN1(v).toBER()), BigInt(v))
  })
})

test('JS BigInt to ASN1 conversion', (t) => {
  TEST_BIG_INTEGERS.forEach((v, i) => {
    t.deepEqual(lib.JStoASN1(v).toBER(), TEST_BIG_INTEGERS_ASN1[i])
  })
})

test('ASN1 to Js BigInt conversion from byte code', (t) => {
  TEST_BIG_INTEGERS_ASN1.forEach((v, i) => {
    const obj = new lib.ASN1Decoder(v)

    t.deepEqual(obj.intoBigInt(), TEST_BIG_INTEGERS[i])
    t.deepEqual(lib.ASN1toJS(v), TEST_BIG_INTEGERS[i])
  })
})

test('ASN1 to Js BigInt conversion from base64', (t) => {
  const result = BigInt('18591708106338011145')
  const base64 = 'AgkBAgMEBQYHCAk='
  const obj = lib.ASN1Decoder.fromBase64(base64)

  t.deepEqual(obj.intoBigInt(), result)
  t.deepEqual(lib.ASN1toJS(base64), result)
})

test('ASN1 to Js BigInt conversion round trip', (t) => {
  TEST_BIG_INTEGERS_ASN1.forEach((v, i) => {
    const js = new lib.ASN1Decoder(v)

    t.deepEqual(js.intoBigInt(), TEST_BIG_INTEGERS[i])
    t.deepEqual(
      lib.JStoASN1(lib.ASN1toJS(v)).toBER(),
      TEST_BIG_INTEGERS_ASN1[i],
    )
  })
})

test('JS BigInt to Buffer conversion helper', (t) => {
  TEST_BIG_INTEGERS.forEach((v) => {
    const buffer = lib.BigIntToBuffer(v)
    const nodeFuncVal = NodeASN1BigIntToBuffer(v)

    // Node function has a bug with negative numbers.
    if (v > 0) {
      t.deepEqual(nodeFuncVal, buffer)
    }

    t.deepEqual(lib.BufferToBigInt(buffer), v)
  })
})

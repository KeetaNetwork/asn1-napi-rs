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
  new Uint8Array([0x02, 0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]).buffer,
  new Uint8Array([0x02, 0x09, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf7]).buffer,
  new Uint8Array([
    0x02, 0x21, 0x00, 0xd1, 0x64, 0xbe, 0x58, 0x60, 0x2b, 0x59, 0x8a, 0xbf, 0x3e, 0x63, 0xd5, 0x50, 0x3c, 0xc9, 0x91,
    0x59, 0x80, 0x65, 0x83, 0x26, 0x10, 0x34, 0x4d, 0x74, 0xc2, 0xa4, 0x7d, 0x27, 0x90, 0x6b, 0xc4,
  ]).buffer,
  new Uint8Array([
    0x02, 0x41, 0x00, 0xeb, 0xa6, 0xda, 0xd1, 0x02, 0xb4, 0xef, 0x35, 0x6b, 0xb2, 0x16, 0x24, 0x38, 0x5d, 0xdc, 0x39,
    0xa5, 0xba, 0xd5, 0x3d, 0x5c, 0x92, 0x7f, 0x50, 0xca, 0x67, 0x92, 0x04, 0x4f, 0xb2, 0x13, 0xb1, 0x09, 0x3c, 0x39,
    0xeb, 0x37, 0xa8, 0x39, 0xe0, 0xac, 0x41, 0x68, 0x08, 0xd1, 0x54, 0x59, 0x53, 0xde, 0x26, 0x5e, 0xe2, 0xa4, 0xed,
    0x41, 0xf5, 0xd1, 0xa0, 0x29, 0x21, 0xa0, 0x28, 0x33, 0xaa,
  ]).buffer,
]

const TEST_STRINGS = ['test', 'This is a Test String!\uD83D\uDE03']

const TEST_STRINGS_ASN1 = [
  new Uint8Array([0x13, 0x4, 0x74, 0x65, 0x73, 0x74]).buffer,
  new Uint8Array([
    0x13, 0x1a, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x74,
    0x72, 0x69, 0x6e, 0x67, 0x21, 0xf0, 0x9f, 0x98, 0x83,
  ]).buffer,
  // UTF-16
  // [
  //   0x13, 0x18, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x74,
  //   0x72, 0x69, 0x6e, 0x67, 0x21, 0x3d, 0x03,
  // ],
]

const TEST_DATES = [new Date(0), new Date('2022-09-26T10:00:00.000+00:00')]

const TEST_DATES_ASN1 = [
  new Uint8Array([
    0x18, 0x13, 0x31, 0x39, 0x37, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2e, 0x30, 0x30,
    0x30, 0x5a,
  ]).buffer,
  new Uint8Array([
    0x18, 0x13, 0x32, 0x30, 0x32, 0x32, 0x30, 0x39, 0x32, 0x36, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2e, 0x30, 0x30,
    0x30, 0x5a,
  ]).buffer,
]

const TEST_OIDS: lib.ASN1OID[] = [
  { type: 'oid', oid: 'sha256' },
  { type: 'oid', oid: 'commonName' },
  { type: 'oid', oid: '1.2.3.4' },
]

const TEST_OIDS_ASN1 = [
  new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]).buffer,
  new Uint8Array([0x06, 0x03, 0x55, 0x04, 0x03]).buffer,
  new Uint8Array([0x06, 0x03, 0x2a, 0x03, 0x04]).buffer,
]

const TEST_CONTEXT_TAGS: lib.ASN1ContextTag[] = [
  {
    type: 'context',
    value: 0,
    contains: [
      { type: 'oid', oid: 'sha3-256' },
      [
        Buffer.from(
          new Uint8Array([
            0x2a, 0xff, 0x4b, 0x48, 0x22, 0x1b, 0xd1, 0x97, 0xd8, 0xc4, 0xcc, 0xaf, 0x17, 0x37, 0x10, 0x81, 0xb2, 0xb3,
            0x93, 0xc4, 0xf2, 0x3a, 0xfc, 0xaf, 0x5f, 0x26, 0x23, 0x36, 0x76, 0xcd, 0x84, 0x3a,
          ]),
        ),
        Buffer.from(
          new Uint8Array([
            0x83, 0xa0, 0xcf, 0xb4, 0xd1, 0x53, 0xac, 0x34, 0xe5, 0xb2, 0x4b, 0x4c, 0x74, 0xfd, 0x50, 0x80, 0x3c, 0x20,
            0xb7, 0xa7, 0xa8, 0x82, 0xdc, 0x94, 0xb0, 0x0d, 0xd4, 0xe9, 0x30, 0x7f, 0xf9, 0xaf,
          ]),
        ),
      ],
    ],
  },
  { type: 'context', value: 3, contains: 42n },
  {
    type: 'context',
    value: 5,
    contains: [{ type: 'set', name: { type: 'oid', oid: '2.15216.1.999' }, value: 'Test' }, 100n],
  },
]

const TEST_CONTEXT_TAGS_ASN1 = [
  new Uint8Array([
    0xa0, 0x53, 0x30, 0x51, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x30, 0x44, 0x04, 0x20,
    0x2a, 0xff, 0x4b, 0x48, 0x22, 0x1b, 0xd1, 0x97, 0xd8, 0xc4, 0xcc, 0xaf, 0x17, 0x37, 0x10, 0x81, 0xb2, 0xb3, 0x93,
    0xc4, 0xf2, 0x3a, 0xfc, 0xaf, 0x5f, 0x26, 0x23, 0x36, 0x76, 0xcd, 0x84, 0x3a, 0x04, 0x20, 0x83, 0xa0, 0xcf, 0xb4,
    0xd1, 0x53, 0xac, 0x34, 0xe5, 0xb2, 0x4b, 0x4c, 0x74, 0xfd, 0x50, 0x80, 0x3c, 0x20, 0xb7, 0xa7, 0xa8, 0x82, 0xdc,
    0x94, 0xb0, 0x0d, 0xd4, 0xe9, 0x30, 0x7f, 0xf9, 0xaf,
  ]).buffer,
  new Uint8Array([0xa3, 0x03, 0x02, 0x01, 0x2a]).buffer,
  new Uint8Array([
    0xa5, 0x16, 0x30, 0x14, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x05, 0xf7, 0x40, 0x01, 0x87, 0x67, 0x13, 0x04, 0x54, 0x65,
    0x73, 0x74, 0x02, 0x01, 0x64,
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

test('JS boolean to ASN1 conversion', (t) => {
  t.deepEqual(lib.JStoASN1(true).toBER(), new Uint8Array([0x1, 0x1, 0xff]).buffer)
  t.deepEqual(lib.JStoASN1(false).toBER(), new Uint8Array([0x1, 0x1, 0x0]).buffer)
})

test('JS integer to ASN1 conversion', (t) => {
  TEST_INTEGERS.map((v, i) => {
    t.deepEqual(lib.JStoASN1(v).toBER(), TEST_INTEGERS_ASN1[i])
  })
})

test('JS BigInt to ASN1 conversion', (t) => {
  TEST_BIG_INTEGERS.map((v, i) => {
    t.deepEqual(lib.JStoASN1(v).toBER(), TEST_BIG_INTEGERS_ASN1[i])
  })
})

test('JS string to ASN1 conversion', (t) => {
  TEST_STRINGS.map((v, i) => {
    t.deepEqual(lib.JStoASN1(v).toBER(), TEST_STRINGS_ASN1[i])
  })
})

test('JS number Array to ASN1 conversion', (t) => {
  t.deepEqual(
    lib.JStoASN1([1n, 2n, 3n, 4n, 5n]).toBER(),
    new Uint8Array([
      0x30, 0x0f, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03, 0x02, 0x01, 0x04, 0x02, 0x01, 0x05,
    ]).buffer,
  )
})

test('JS mixed Array to ASN1 conversion', (t) => {
  const oid: lib.ASN1OID = { type: 'oid', oid: 'commonName' }
  const set: lib.ASN1Set = { type: 'set', name: oid, value: 'test' }

  t.deepEqual(
    lib.JStoASN1([1, 'test', oid, set, 532434n]).toBER(),
    new Uint8Array([
      0x30, 0x22, 0x02, 0x01, 0x01, 0x13, 0x04, 0x74, 0x65, 0x73, 0x74, 0x06, 0x03, 0x55, 0x04, 0x03, 0x31, 0x0d, 0x30,
      0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x04, 0x74, 0x65, 0x73, 0x74, 0x02, 0x03, 0x08, 0x1f, 0xd2,
    ]).buffer,
  )
})

test('JS Buffer to ASN1 conversion', (t) => {
  t.deepEqual(
    lib.JStoASN1(Buffer.from(new Uint8Array([1, 2, 3, 4, 5]))).toBER(),
    new Uint8Array([0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]).buffer,
  )
})

test('JS bit string to ASN1 conversion', (t) => {
  const data = Buffer.from(new Uint8Array([0xa, 0x10, 20, 32, 9]))
  const input: lib.ASN1BitString = { type: 'bitstring', value: data }

  t.deepEqual(lib.JStoASN1(input).toBER(), new Uint8Array([0x03, 0x06, 0x00, 0xa, 0x10, 0x14, 0x20, 0x9]).buffer)
})

test('JS ASN1OID to ASN1 conversion', (t) => {
  TEST_OIDS.map((v, i) => {
    t.deepEqual(lib.JStoASN1(v).toBER(), TEST_OIDS_ASN1[i])
  })
})

test('JS ASN1Set to ASN1 conversion', (t) => {
  const oid: lib.ASN1OID = { type: 'oid', oid: 'commonName' }
  const set: lib.ASN1Set = { type: 'set', name: oid, value: 'test' }

  t.deepEqual(
    lib.JStoASN1(set).toBER(),
    new Uint8Array([0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x04, 0x74, 0x65, 0x73, 0x74]).buffer,
  )
})

test('JS Date to ASN1 conversion', (t) => {
  TEST_DATES.map((v, i) => {
    t.deepEqual(lib.JStoASN1(v).toBER(), TEST_DATES_ASN1[i])
  })
})

test('JS Context Tag to ASN1 conversion', (t) => {
  TEST_CONTEXT_TAGS.map((v, i) => {
    t.deepEqual(lib.JStoASN1(v).toBER(), TEST_CONTEXT_TAGS_ASN1[i])
  })
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
  const asn1_true = lib.JStoASN1(input_true).toBER()
  const asn1_false = lib.JStoASN1(input_false).toBER()
  const js_true = new lib.Asn1(asn1_true)
  const js_false = new lib.Asn1(asn1_false)

  t.deepEqual(js_true.intoBool(), input_true)
  t.deepEqual(js_false.intoBool(), input_false)
  t.deepEqual(lib.ASN1toJS(lib.JStoASN1(input_true).toBER()), input_true)
  t.deepEqual(lib.ASN1toJS(lib.JStoASN1(input_false).toBER()), input_false)
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
    t.deepEqual(lib.ASN1toJS(lib.JStoASN1(v).toBER()), BigInt(v))
  })
})

test('ASN1 to Js BigInt conversion from byte code', (t) => {
  TEST_BIG_INTEGERS_ASN1.map((v, i) => {
    const data = new Uint8Array(v)
    const obj = new lib.Asn1(Array.from(data))

    t.deepEqual(obj.intoBigInt(), TEST_BIG_INTEGERS[i])
    t.deepEqual(lib.ASN1toJS(v), TEST_BIG_INTEGERS[i])
  })
})

test('ASN1 to Js BigInt conversion from base64', (t) => {
  const result = BigInt('18591708106338011145')
  const base64 = 'AgkBAgMEBQYHCAk='
  const obj = lib.Asn1.fromBase64(base64)

  t.deepEqual(obj.intoBigInt(), result)
  t.deepEqual(lib.ASN1toJS(base64), result)
})

test('ASN1 to Js BigInt conversion round trip', (t) => {
  const input = BigInt('18591708106338011145')
  const asn1 = lib.JStoASN1(input)
  const js = new lib.Asn1(asn1.toBER())

  t.deepEqual(js.intoBigInt(), input)
  t.deepEqual(lib.ASN1toJS(lib.JStoASN1(input).toBER()), input)
})

test('ASN1 to Js string conversion from byte code', (t) => {
  TEST_STRINGS_ASN1.map((v, i) => {
    t.deepEqual(lib.ASN1toJS(v), TEST_STRINGS[i])
  })
})

test('ASN1 to Js string conversion from base64', (t) => {
  const obj = lib.Asn1.fromBase64('EwR0ZXN0')

  t.deepEqual(obj.intoString(), 'test')
})

test('ASN1 to Js string conversion round trip', (t) => {
  TEST_STRINGS_ASN1.map((v, i) => {
    const data = new Uint8Array(v)
    const js = new lib.Asn1(Array.from(data))

    t.deepEqual(js.intoString(), TEST_STRINGS[i])
    t.deepEqual(lib.JStoASN1(lib.ASN1toJS(v)).toBER(), TEST_STRINGS_ASN1[i])
  })
})

test('ASN1 to Js Date conversion from byte code', (t) => {
  const obj = new lib.Asn1([
    0x18, 0xf, 0x32, 0x30, 0x32, 0x32, 0x30, 0x39, 0x32, 0x36, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
  ])
  const date = obj.intoDate()

  t.true(date instanceof Date)
  t.deepEqual(date, new Date('2022-09-26T10:00:00.000+00:00'))
})

test('ASN1 to Js Date conversion from base64', (t) => {
  const obj = lib.Asn1.fromBase64('GA8yMDIyMDkyNjEwMDAwMFo=')
  const date = obj.intoDate()

  t.true(date instanceof Date)
  t.deepEqual(date, new Date('2022-09-26T10:00:00.000+00:00'))
})

test('ASN1 to Js Date conversion round trip', (t) => {
  const input = new Date('2022-09-26T10:00:00.000+00:00')
  const asn1 = lib.JStoASN1(input)
  const js = new lib.Asn1(asn1.toBER())

  t.deepEqual(js.intoDate(), input)
  t.deepEqual(lib.ASN1toJS(lib.JStoASN1(input).toBER()), input)
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
  const js = new lib.Asn1(asn1.toBER())

  t.deepEqual(js.intoBuffer(), input)
  t.deepEqual(lib.ASN1toJS(lib.JStoASN1(input).toBER()), input)
})

test('ASN1 to Js bit string conversion from byte code', (t) => {
  const obj = new lib.Asn1([
    0x03, 0x21, 0x00, 0xc5, 0xb8, 0xdd, 0xf7, 0x48, 0xe3, 0x07, 0x9e, 0xa1, 0x87, 0x86, 0x49, 0x35, 0xdd, 0xb8, 0xc2,
    0xea, 0x4e, 0xaa, 0x9c, 0xdf, 0x06, 0xaf, 0xe2, 0x83, 0xed, 0xb5, 0x5d, 0x6b, 0x38, 0x49, 0xb4,
  ])

  t.deepEqual(obj.intoBitString(), {
    type: 'bitstring',
    value: Buffer.from('xbjd90jjB56hh4ZJNd24wupOqpzfBq/ig+21XWs4SbQ=', 'base64'),
  })
})

test('ASN1 to Js bit string conversion from base64', (t) => {
  const obj = lib.Asn1.fromBase64('AwYAChAUIAk=')

  t.deepEqual(obj.intoBitString(), {
    type: 'bitstring',
    value: Buffer.from(new Uint8Array([0xa, 0x10, 20, 32, 9])),
  })
})

test('ASN1 to Js bit string conversion round trip', (t) => {
  const input: lib.ASN1BitString = {
    type: 'bitstring',
    value: Buffer.from('xbjd90jjB56hh4ZJNd24wupOqpzfBq/ig+21XWs4SbQ=', 'base64'),
  }
  t.deepEqual(lib.ASN1toJS(lib.JStoASN1(input).toBER()), input)
})

test('ASN1 to Js Context Tag conversion from byte code', (t) => {
  TEST_CONTEXT_TAGS_ASN1.map((v, i) => {
    const data = new Uint8Array(v)
    const obj = new lib.Asn1(Array.from(data))

    t.deepEqual(obj.intoContextTag(), TEST_CONTEXT_TAGS[i])
  })
})

test('ASN1 to Js Context Tag conversion from base64', (t) => {
  const obj = lib.Asn1.fromBase64(
    'oFMwUQYJYIZIAWUDBAIIMEQEICr/S0giG9GX2MTMrxc3EIGys5PE8jr8r18mIzZ2zYQ6BCCDoM+00VOsNOWyS0x0/VCAPCC3p6iC3JSwDdTpMH/5rw==',
  )

  t.deepEqual(obj.intoContextTag(), TEST_CONTEXT_TAGS[0])
})

test('ASN1 to Js Context Tag conversion round trip', (t) => {
  TEST_CONTEXT_TAGS.map((v) => {
    t.deepEqual(lib.ASN1toJS(lib.JStoASN1(v).toBER()), v)
  })
})

test('ASN1 to Js ASN1OID conversion from byte code', (t) => {
  TEST_OIDS_ASN1.map((v, i) => {
    const data = new Uint8Array(v)
    const obj = new lib.Asn1(Array.from(data))

    t.deepEqual(obj.intoOid(), TEST_OIDS[i])
  })
})

test('ASN1 to Js ASN1OID conversion from base64', (t) => {
  const oid: lib.ASN1OID = { type: 'oid', oid: 'sha256' }
  const obj = lib.Asn1.fromBase64('BglghkgBZQMEAgE=')

  t.deepEqual(obj.intoOid(), oid)
})

test('ASN1 to Js ASN1OID conversion round trip', (t) => {
  const input: lib.ASN1OID = { type: 'oid', oid: 'sha256' }
  const asn1 = lib.JStoASN1(input).toBER()
  const js = new lib.Asn1(asn1)

  t.deepEqual(js.intoOid(), input)
  t.deepEqual(lib.ASN1toJS(lib.JStoASN1(input).toBER()), input)
})

test('ASN1 to Js ASN1Set conversion from byte code', (t) => {
  const oid: lib.ASN1OID = { type: 'oid', oid: 'commonName' }
  const set: lib.ASN1Set = { type: 'set', name: oid, value: 'test' }
  const obj = new lib.Asn1([0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x04, 0x74, 0x65, 0x73, 0x74])

  t.deepEqual(obj.intoSet(), set)
})

test('ASN1 to Js ASN1Set conversion from base64', (t) => {
  const oid: lib.ASN1OID = { type: 'oid', oid: 'commonName' }
  const set: lib.ASN1Set = { type: 'set', name: oid, value: 'test' }
  const obj = lib.Asn1.fromBase64('MQ0wCwYDVQQDEwR0ZXN0')

  t.deepEqual(obj.intoSet(), set)
})

test('ASN1 to Js ASN1Set conversion round trip', (t) => {
  const oid: lib.ASN1OID = { type: 'oid', oid: 'commonName' }
  const input: lib.ASN1Set = { type: 'set', name: oid, value: 'test' }
  const asn1 = lib.JStoASN1(input)
  const js = new lib.Asn1(asn1.toBER())

  t.deepEqual(js.intoSet(), input)
  t.deepEqual(lib.ASN1toJS(lib.JStoASN1(input).toBER()), input)
})

test('ASN1 to Js number array conversion from byte code', (t) => {
  const input = [1n, 2n, 3n, 4n, 5n]
  const obj = new lib.Asn1([
    0x30, 0x0f, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03, 0x02, 0x01, 0x04, 0x02, 0x01, 0x05,
  ])

  t.deepEqual(obj.intoArray(), input)
})

test('ASN1 to Js number array conversion from base64', (t) => {
  const input = [1n, 2n, 3n, 4n, 5n]
  const obj = lib.Asn1.fromBase64('MA8CAQECAQICAQMCAQQCAQU=')

  t.deepEqual(obj.intoArray(), input)
})

test('ASN1 to Js number array conversion round trip', (t) => {
  const input = [1n, 2n, 3n, 4n, 5n]
  const asn1 = lib.JStoASN1(input)
  const js = new lib.Asn1(asn1.toBER())

  t.deepEqual(js.intoArray(), input)
  t.deepEqual(lib.ASN1toJS(lib.JStoASN1(input).toBER()), input)
})

test('ASN1 to Js mixed array conversion from byte code', (t) => {
  const oid: lib.ASN1OID = { type: 'oid', oid: 'commonName' }
  const set: lib.ASN1Set = { type: 'set', name: oid, value: 'test' }
  const input = [1n, 'test', oid, set, 532434n]

  const obj = new lib.Asn1([
    0x30, 0x22, 0x02, 0x01, 0x01, 0x13, 0x04, 0x74, 0x65, 0x73, 0x74, 0x06, 0x03, 0x55, 0x04, 0x03, 0x31, 0x0d, 0x30,
    0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x04, 0x74, 0x65, 0x73, 0x74, 0x02, 0x03, 0x08, 0x1f, 0xd2,
  ])

  t.deepEqual(obj.intoArray(), input)
})

test('ASN1 to Js mixed array conversion from base64', (t) => {
  const oid: lib.ASN1OID = { type: 'oid', oid: 'commonName' }
  const set: lib.ASN1Set = { type: 'set', name: oid, value: 'test' }
  const input = [1n, 'test', oid, set, 532434n]
  const obj = lib.Asn1.fromBase64('MCICAQETBHRlc3QGA1UEAzENMAsGA1UEAxMEdGVzdAIDCB/S')

  t.deepEqual(obj.intoArray(), input)
})

test('ASN1 to Js mixed array conversion round trip', (t) => {
  const input = [1n, 2n, 3n, 4n, 5n]
  const asn1 = lib.JStoASN1(input)
  const js = new lib.Asn1(asn1.toBER())

  t.deepEqual(js.intoArray(), input)
  t.deepEqual(lib.ASN1toJS(lib.JStoASN1(input).toBER()), input)
})

test('JS integer to BigInt conversion helper', (t) => {
  t.deepEqual(lib.IntegerToBigInt(42), BigInt('42'))
})

test('JS BigInt to Buffer conversion helper', (t) => {
  TEST_BIG_INTEGERS.map((v) => {
    const buffer = lib.BigIntToBuffer(v)
    const nodeFuncVal = NodeASN1BigIntToBuffer(v)

    // Node function has a bug with negative numbers.
    if (v > 0) {
      t.deepEqual(nodeFuncVal, buffer)
    }

    t.deepEqual(lib.BufferToBigInt(buffer), v)
  })
})

test('JS string to BigInt conversion helper', (t) => {
  TEST_BIG_INTEGERS.map((v) => {
    t.deepEqual(lib.StringToBigInt(v.toString()), v)
  })
})

test('Complex structure', (t) => {
  const input = [
    [
      { type: 'context', value: 0, contains: 2n } as lib.ASN1ContextTag,
      1n,
      [{ type: 'oid', oid: 'sha3-256WithEcDSA' } as lib.ASN1OID],
      [
        {
          type: 'set',
          name: { type: 'oid', oid: 'commonName' } as lib.ASN1OID,
          value: 'keeta_aaaervzquo7sam2j4vrnmbwpln6dugaty37qqlduylti6pejpuu3xeohxxbupge',
        } as lib.ASN1Set,
      ],
      [new Date('2022-09-26T10:10:32.420+00:00')],
      [{ type: 'set', name: { type: 'oid', oid: 'serialNumber' } as lib.ASN1OID, value: '1' }],
      [
        [{ type: 'oid', oid: 'ecdsa' } as lib.ASN1OID, { type: 'oid', oid: 'secp256k1' } as lib.ASN1OID],
        {
          type: 'bitstring',
          value: Buffer.from('xbjd90jjB56hh4ZJNd24wupOqpzfBq/ig+21XWs4SbQ=', 'base64'),
        } as lib.ASN1BitString,
      ],
      {
        type: 'context',
        value: 3,
        contains: [
          { type: 'oid', oid: 'sha3-256WithEcDSA' } as lib.ASN1OID,
          true,
          Buffer.from('xbjd90jjB56hh4ZJNd24wupOqpzfBq/ig+21XWs4SbQ=', 'base64'),
        ],
      } as lib.ASN1ContextTag,
    ],
    [{ type: 'oid', oid: 'sha3-256WithEcDSA' }],
    {
      type: 'bitstring',
      value: Buffer.from('xbjd90jjB56hh4ZJNd24wupOqpzfBq/ig+21XWs4SbQ=', 'base64'),
    } as lib.ASN1BitString,
  ]

  const ber = lib.JStoASN1(input).toBER()
  const data = lib.ASN1toJS(ber)

  t.deepEqual(data, input)
})

test('Node ASN1 Tests', (t) => {
  const integers = [-1, -0x7f, -0x80, -0xffffff, -0x7fffff]
  const input = [
    BigInt(-1),
    BigInt(-0xffffff),
    BigInt(-0x7fffff),
    BigInt(0),
    BigInt(0x7f),
    BigInt(0x80),
    BigInt('0x8bcbbf49c554d3f1b26e39005546b9f5910a12c5a61dc4cff707367a548264c2'),
    { type: 'oid', oid: '1.2.3.4' } as lib.ASN1OID,
    { type: 'context', value: 3, contains: 42n } as lib.ASN1ContextTag,
    {
      type: 'bitstring',
      value: Buffer.from('xbjd90jjB56hh4ZJNd24wupOqpzfBq/ig+21XWs4SbQ=', 'base64'),
    } as lib.ASN1BitString,
    { type: 'set', name: { type: 'oid', oid: '2.15216.1.999' }, value: 'Test' } as lib.ASN1Set,
    Buffer.from('This is a Test String!\uD83D\uDE03'),
    'This is a Test String!',
    'This is a Test String!\uD83D\uDE03',
    new Date(0),
    new Date('2022-09-26T10:10:32.420+00:00'),
    new Date(),
    true,
    false,
    null,
    {
      type: 'context',
      value: 5,
      contains: [{ type: 'set', name: { type: 'oid', oid: '2.15216.1.999' }, value: 'Test' }, 100n],
    } as lib.ASN1ContextTag,
  ]

  input.map((v) => {
    t.deepEqual(lib.ASN1toJS(lib.JStoASN1(v).toBER()), v)
  })

  integers.map((v) => {
    t.deepEqual(lib.ASN1toJS(lib.JStoASN1(v).toBER()), BigInt(v))
  })

  const asn1 = lib.JStoASN1(input)
  const js = new lib.Asn1(asn1.toBER())

  t.deepEqual(js.intoArray(), input)
  t.deepEqual(lib.ASN1toJS(asn1.toBER()), input)
})

test('Error handling', (t) => {
  const js = new lib.Asn1(Buffer.from('Never gonna give you up'))

  t.throws(js.intoString)
})

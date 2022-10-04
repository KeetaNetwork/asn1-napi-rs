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
  0n,
  0x7fn,
  0x80n,
  0x10203040506070809n,
  -0x10203040506070809n,
  0xd164be58602b598abf3e63d5503cc991598065832610344d74c2a47d27906bc4n,
  0xeba6dad102b4ef356bb21624385ddc39a5bad53d5c927f50ca6792044fb213b1093c39eb37a839e0ac416808d1545953de265ee2a4ed41f5d1a02921a02833aan,
]
const TEST_BIG_INTEGERS_ASN1 = [
  [0x02, 0x01, 0x00],
  [0x02, 0x01, 0x7f],
  [0x02, 0x02, 0x00, 0x80],
  [0x02, 0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09],
  [0x02, 0x09, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf7],
  [
    0x02, 0x21, 0x00, 0xd1, 0x64, 0xbe, 0x58, 0x60, 0x2b, 0x59, 0x8a, 0xbf, 0x3e, 0x63, 0xd5, 0x50, 0x3c, 0xc9, 0x91,
    0x59, 0x80, 0x65, 0x83, 0x26, 0x10, 0x34, 0x4d, 0x74, 0xc2, 0xa4, 0x7d, 0x27, 0x90, 0x6b, 0xc4,
  ],
  [
    0x02, 0x41, 0x00, 0xeb, 0xa6, 0xda, 0xd1, 0x02, 0xb4, 0xef, 0x35, 0x6b, 0xb2, 0x16, 0x24, 0x38, 0x5d, 0xdc, 0x39,
    0xa5, 0xba, 0xd5, 0x3d, 0x5c, 0x92, 0x7f, 0x50, 0xca, 0x67, 0x92, 0x04, 0x4f, 0xb2, 0x13, 0xb1, 0x09, 0x3c, 0x39,
    0xeb, 0x37, 0xa8, 0x39, 0xe0, 0xac, 0x41, 0x68, 0x08, 0xd1, 0x54, 0x59, 0x53, 0xde, 0x26, 0x5e, 0xe2, 0xa4, 0xed,
    0x41, 0xf5, 0xd1, 0xa0, 0x29, 0x21, 0xa0, 0x28, 0x33, 0xaa,
  ],
]

const TEST_STRINGS = [
  'test',
  //'This is a Test String!\uD83D\uDE03'
]

const TEST_STRINGS_ASN1 = [
  [0x13, 0x4, 0x74, 0x65, 0x73, 0x74],
  // [
  //   0x13, 0x18, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x74,
  //   0x72, 0x69, 0x6e, 0x67, 0x21, 0x3d, 0x03,
  // ],
]

const TEST_DATES = [new Date(0), new Date('2022-09-26T10:00:00.000+00:00')]

const TEST_DATES_ASN1 = [
  [0x18, 0x0f, 0x31, 0x39, 0x37, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a],
  [0x18, 0x0f, 0x32, 0x30, 0x32, 0x32, 0x30, 0x39, 0x32, 0x36, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a],
]

const TEST_OIDS = [
  { type: 'oid', oid: 'sha256' },
  { type: 'oid', oid: 'commonName' },
  { type: 'oid', oid: '1.2.3.4' },
]

const TEST_OIDS_ASN1 = [
  [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
  [0x06, 0x03, 0x55, 0x04, 0x03],
  [0x06, 0x03, 0x2a, 0x03, 0x04],
]

const TEST_CONTEXT_TAGS = [
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
  {
    type: 'context',
    value: 5,
    contains: [{ type: 'set', name: { type: 'oid', oid: '2.15216.1.999' }, value: 'Test' }, 100],
  },
  { type: 'context', value: 3, contains: 42n },
]
const TEST_CONTEXT_TAGS_ASN1 = [
  [
    0xa0, 0x53, 0x30, 0x51, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x30, 0x44, 0x04, 0x20,
    0x2a, 0xff, 0x4b, 0x48, 0x22, 0x1b, 0xd1, 0x97, 0xd8, 0xc4, 0xcc, 0xaf, 0x17, 0x37, 0x10, 0x81, 0xb2, 0xb3, 0x93,
    0xc4, 0xf2, 0x3a, 0xfc, 0xaf, 0x5f, 0x26, 0x23, 0x36, 0x76, 0xcd, 0x84, 0x3a, 0x04, 0x20, 0x83, 0xa0, 0xcf, 0xb4,
    0xd1, 0x53, 0xac, 0x34, 0xe5, 0xb2, 0x4b, 0x4c, 0x74, 0xfd, 0x50, 0x80, 0x3c, 0x20, 0xb7, 0xa7, 0xa8, 0x82, 0xdc,
    0x94, 0xb0, 0x0d, 0xd4, 0xe9, 0x30, 0x7f, 0xf9, 0xaf,
  ],
  [
    0xa5, 0x16, 0x30, 0x14, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x05, 0xf7, 0x40, 0x01, 0x87, 0x67, 0x13, 0x04, 0x54, 0x65,
    0x73, 0x74, 0x02, 0x01, 0x64,
  ],
  [0xa3, 0x03, 0x02, 0x01, 0x2a],
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
  TEST_STRINGS.map((v, i) => {
    t.deepEqual(lib.JStoASN1(v), TEST_STRINGS_ASN1[i])
  })
})

test('JS number Array to ASN1 conversion', (t) => {
  t.deepEqual(
    lib.JStoASN1([1n, 2n, 3n, 4n, 5n]),
    [0x30, 0x0f, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03, 0x02, 0x01, 0x04, 0x02, 0x01, 0x05],
  )
})

test('JS mixed Array to ASN1 conversion', (t) => {
  const oid: lib.ASN1OID = { type: 'oid', oid: 'commonName' }
  const set: lib.ASN1Set = { type: 'set', name: oid, value: 'test' }

  t.deepEqual(
    lib.JStoASN1([1, 'test', oid, set, 532434n]),
    [
      0x30, 0x22, 0x02, 0x01, 0x01, 0x13, 0x04, 0x74, 0x65, 0x73, 0x74, 0x06, 0x03, 0x55, 0x04, 0x03, 0x31, 0x0d, 0x30,
      0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x04, 0x74, 0x65, 0x73, 0x74, 0x02, 0x03, 0x08, 0x1f, 0xd2,
    ],
  )
})

test('JS Buffer to ASN1 conversion', (t) => {
  t.deepEqual(lib.JStoASN1(Buffer.from(new Uint8Array([1, 2, 3, 4, 5]))), [0x04, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05])
})

test('JS bit string to ASN1 conversion', (t) => {
  const data = Buffer.from(new Uint8Array([0xa, 0x10, 20, 32, 9]))
  const input = { type: 'bitstring', value: data }

  t.deepEqual(lib.JStoASN1(input), [0x03, 0x06, 0x00, 0xa, 0x10, 0x14, 0x20, 0x9])
})

test('JS ASN1OID to ASN1 conversion', (t) => {
  TEST_OIDS.map((v, i) => {
    t.deepEqual(lib.JStoASN1(v), TEST_OIDS_ASN1[i])
  })
})

test('JS ASN1Set to ASN1 conversion', (t) => {
  const oid: lib.ASN1OID = { type: 'oid', oid: 'commonName' }
  const set: lib.ASN1Set = { type: 'set', name: oid, value: 'test' }

  t.deepEqual(
    lib.JStoASN1(set),
    [0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x04, 0x74, 0x65, 0x73, 0x74],
  )
})

test('JS Date to ASN1 conversion', (t) => {
  TEST_DATES.map((v, i) => {
    t.deepEqual(lib.JStoASN1(v), TEST_DATES_ASN1[i])
  })
})

test('JS Context Tag to ASN1 conversion', (t) => {
  TEST_CONTEXT_TAGS.map((v, i) => {
    t.deepEqual(lib.JStoASN1(v), TEST_CONTEXT_TAGS_ASN1[i])
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
  const asn1_true = lib.JStoASN1(input_true)
  const asn1_false = lib.JStoASN1(input_false)
  const js_true = new lib.Asn1(asn1_true)
  const js_false = new lib.Asn1(asn1_false)

  t.deepEqual(js_true.intoBool(), input_true)
  t.deepEqual(js_false.intoBool(), input_false)
  t.deepEqual(lib.ASN1toJS(lib.JStoASN1(input_true)), input_true)
  t.deepEqual(lib.ASN1toJS(lib.JStoASN1(input_false)), input_false)
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
    t.deepEqual(lib.ASN1toJS(lib.JStoASN1(v)), BigInt(v))
  })
})

test('ASN1 to Js BigInt conversion from byte code', (t) => {
  const result = BigInt('18591708106338011145')
  const asn1 = [0x02, 0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]
  const obj = new lib.Asn1(asn1)

  t.deepEqual(obj.intoBigInt(), result)
  t.deepEqual(lib.ASN1toJS(asn1), result)
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
  const js = new lib.Asn1(asn1)

  t.deepEqual(js.intoBigInt(), input)
  t.deepEqual(lib.ASN1toJS(lib.JStoASN1(input)), input)
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
    const js = new lib.Asn1(v)

    t.deepEqual(js.intoString(), TEST_STRINGS[i])
    t.deepEqual(lib.JStoASN1(lib.ASN1toJS(v)), TEST_STRINGS_ASN1[i])
  })
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
  t.deepEqual(lib.ASN1toJS(lib.JStoASN1(input)), input)
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
  t.deepEqual(lib.ASN1toJS(lib.JStoASN1(input)), input)
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
  const input = { type: 'bitstring', value: Buffer.from('xbjd90jjB56hh4ZJNd24wupOqpzfBq/ig+21XWs4SbQ=', 'base64') }
  t.deepEqual(lib.ASN1toJS(lib.JStoASN1(input)), input)
})

test('ASN1 to Js Context Tag conversion from byte code', (t) => {
  TEST_CONTEXT_TAGS_ASN1.map((v, i) => {
    const obj = new lib.Asn1(v)

    t.deepEqual(obj.intoContextTag(), TEST_CONTEXT_TAGS[i])
  })
})

test('ASN1 to Js Context Tag conversion from base64', (t) => {
  const obj = lib.Asn1.fromBase64(
    'oFMwUQYJYIZIAWUDBAIIMEQEICr/S0giG9GX2MTMrxc3EIGys5PE8jr8r18mIzZ2zYQ6BCCDoM+00VOsNOWyS0x0/VCAPCC3p6iC3JSwDdTpMH/5rw==',
  )

  t.deepEqual(obj.intoContextTag(), TEST_CONTEXT_TAGS[0])
})

// test('ASN1 to Js Context Tag conversion round trip', (t) => {
//   TEST_CONTEXT_TAGS.map((v) => {
//     t.deepEqual(lib.ASN1toJS(lib.JStoASN1(v)), v)
//   })
// })

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
  t.deepEqual(lib.ASN1toJS(lib.JStoASN1(input)), input)
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
  const js = new lib.Asn1(asn1)

  t.deepEqual(js.intoSet(), input)
  t.deepEqual(lib.ASN1toJS(lib.JStoASN1(input)), input)
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
  const js = new lib.Asn1(asn1)

  t.deepEqual(js.intoArray(), input)
  t.deepEqual(lib.ASN1toJS(lib.JStoASN1(input)), input)
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
  const js = new lib.Asn1(asn1)

  t.deepEqual(js.intoArray(), input)
  t.deepEqual(lib.ASN1toJS(lib.JStoASN1(input)), input)
})

test('JS integer to BigInt conversion helper', (t) => {
  t.deepEqual(lib.ASN1IntegerToBigInt(42), BigInt('42'))
})

test('JS BigInt to Buffer conversion helper', (t) => {
  const input = BigInt('18591708106338011145')
  const buffer = lib.ASN1BigIntToBuffer(input)

  t.deepEqual(BigInt(`0x${buffer.subarray(0, buffer.length).toString('hex')}`), input)
})

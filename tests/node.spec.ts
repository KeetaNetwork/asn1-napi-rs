import test from 'ava'

import * as lib from '../index'

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
          value:
            'keeta_aaaervzquo7sam2j4vrnmbwpln6dugaty37qqlduylti6pejpuu3xeohxxbupge',
        } as lib.ASN1Set,
      ],
      [new Date('2022-09-26T10:10:32.420+00:00')],
      [
        {
          type: 'set',
          name: { type: 'oid', oid: 'serialNumber' } as lib.ASN1OID,
          value: '1',
        },
      ],
      [
        [
          { type: 'oid', oid: 'ecdsa' } as lib.ASN1OID,
          { type: 'oid', oid: 'secp256k1' } as lib.ASN1OID,
        ],
        {
          type: 'bitstring',
          value: Buffer.from(
            'xbjd90jjB56hh4ZJNd24wupOqpzfBq/ig+21XWs4SbQ=',
            'base64',
          ),
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
      value: Buffer.from(
        'xbjd90jjB56hh4ZJNd24wupOqpzfBq/ig+21XWs4SbQ=',
        'base64',
      ),
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
    BigInt(
      '0x8bcbbf49c554d3f1b26e39005546b9f5910a12c5a61dc4cff707367a548264c2',
    ),
    { type: 'oid', oid: '1.2.3.4' } as lib.ASN1OID,
    { type: 'context', value: 3, contains: 42n } as lib.ASN1ContextTag,
    {
      type: 'bitstring',
      value: Buffer.from(
        'xbjd90jjB56hh4ZJNd24wupOqpzfBq/ig+21XWs4SbQ=',
        'base64',
      ),
    } as lib.ASN1BitString,
    {
      type: 'set',
      name: { type: 'oid', oid: '2.15216.1.999' },
      value: 'Test',
    } as lib.ASN1Set,
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
      contains: [
        {
          type: 'set',
          name: { type: 'oid', oid: '2.15216.1.999' },
          value: 'Test',
        },
        100n,
      ],
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

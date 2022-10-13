import * as asn1js from 'asn1js'
import b from 'benny'

import * as lib from '../index'

//import * as lib from '../index'

interface ASN1Object {
  type: string
}

interface ASN1OID extends ASN1Object {
  type: 'oid'
  oid: string
}

interface ASN1Set extends ASN1Object {
  type: 'set'
  name: ASN1OID
  value: string
}

interface ASN1ContextTag extends ASN1Object {
  type: 'context'
  value: number
  contains: ASN1AnyJS
}

interface ASN1BitString extends ASN1Object {
  type: 'bitstring'
  value: Buffer
}

type ASN1AnyJS =
  | any[]
  | bigint
  | bigint
  | number
  | Date
  | Buffer
  | ASN1OID
  | ASN1Set
  | ASN1ContextTag
  | ASN1BitString
  | string
  | boolean
  | null
type ASN1AnyASN =
  | asn1js.Sequence
  | asn1js.Set
  | asn1js.Integer
  | asn1js.GeneralizedTime
  | asn1js.Null
  | asn1js.OctetString
  | asn1js.BitString
  | asn1js.ObjectIdentifier
  | asn1js.Constructed
  | asn1js.Boolean
  | asn1js.PrintableString

function BigIntToBuffer(value: bigint | bigint): Buffer {
  /**
   * Convert value to Hex
   */
  let valueStr = value.toString(16)

  /**
   * Determine if the value is negative
   */
  let isNegative = false
  if (valueStr.startsWith('-')) {
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

function isASN1OID(input: any): input is ASN1OID {
  if (typeof input !== 'object') {
    return false
  }

  if (input.type !== 'oid') {
    return false
  }

  if (typeof input.oid !== 'string') {
    return false
  }

  return true
}

function isASN1Set(input: any): input is ASN1Set {
  if (typeof input !== 'object') {
    return false
  }

  if (input.type !== 'set') {
    return false
  }

  if (!isASN1OID(input.name)) {
    return false
  }

  if (typeof input.value !== 'string') {
    return false
  }

  return true
}

function isASN1ContextTag(input: any): input is ASN1ContextTag {
  if (typeof input !== 'object') {
    return false
  }

  if (input.type !== 'context') {
    return false
  }

  if (typeof input.value !== 'number') {
    return false
  }

  if (input.contains === undefined) {
    return false
  }

  return true
}

function isASN1BitString(input: any): input is ASN1BitString {
  if (typeof input !== 'object') {
    return false
  }

  if (input.type !== 'bitstring') {
    return false
  }

  if (!(input.value instanceof Buffer)) {
    return false
  }

  return true
}

const oidMapDB: { [k: string]: string } = {
  sha256: '2.16.840.1.101.3.4.2.1',
  'sha3-256': '2.16.840.1.101.3.4.2.8',
  'sha3-256WithEcDSA': '2.16.840.1.101.3.4.3.10',
  sha256WithEcDSA: '1.2.840.10045.4.3.2',
  ecdsa: '1.2.840.10045.2.1',
  ed25519: '1.3.101.112',
  secp256k1: '1.3.132.0.10',
  account: '2.23.42.2.7.11',
  serialNumber: '2.5.4.5',
  member: '2.5.4.31',
  commonName: '2.5.4.3',
  hash: '1.3.6.1.4.1.8301.3.2.2.1.1',
  hashData: '2.16.840.1.101.3.3.1.3',
}

/**
 * Convert a symbolic name into an Object Identifier (OID)
 */
function nameToOID(name: string): string {
  const oid = oidMapDB[name]
  if (oid === undefined) {
    /**
     * If the name looks like an OID, just return it
     */
    if (name.includes('.')) {
      return name
    }

    throw new Error(`Unable to lookup OID for ${name}`)
  }

  return oid
}

/**
 * Convert an Object Identifier into the canonical symbolic name
 */
function oidToName(oid: string | asn1js.ObjectIdentifier): string {
  if (oid instanceof asn1js.ObjectIdentifier) {
    oid = oid.valueBlock.toString()
  }

  for (const checkName in oidMapDB) {
    const checkOID = oidMapDB[checkName]

    if (checkOID === oid) {
      return checkName
    }
  }

  return oid
}

/* XXX:TODO: This does not correctly deal with negative values */
function jsIntegerToBigInt(value: asn1js.Integer): bigint {
  const valueStr = value.toString().split(':')[1].trim()

  return BigInt(valueStr)
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars, no-unused-vars
function JStoASN1(input: ASN1AnyJS): ASN1AnyASN {
  if (Array.isArray(input) || input instanceof Array) {
    const container = new asn1js.Sequence()
    container.valueBlock.value = input.map(function (item) {
      return JStoASN1(item)
    })
    return container
  } else if (typeof input === 'bigint' || input instanceof BigInt) {
    const valueHex = BigIntToBuffer(input as bigint)

    return new asn1js.Integer({ valueHex })
  } else if (typeof input === 'number') {
    return new asn1js.Integer({ value: input })
  } else if (input instanceof Date) {
    return new asn1js.GeneralizedTime({ valueDate: input })
  } else if (input === null) {
    return new asn1js.Null()
  } else if (input instanceof Buffer) {
    return new asn1js.OctetString({ isHexOnly: true, valueHex: input })
  } else if (isASN1BitString(input)) {
    const retval = new asn1js.BitString()

    retval.valueBlock.isHexOnly = true
    retval.valueBlock.valueHex = input.value

    return retval
  } else if (isASN1OID(input)) {
    const oid = nameToOID(input.oid)

    return new asn1js.ObjectIdentifier({ value: oid })
  } else if (isASN1Set(input)) {
    const setContainer = new asn1js.Set()
    const sequenceContainer = new asn1js.Sequence()
    sequenceContainer.valueBlock.value.push(JStoASN1(input.name))
    sequenceContainer.valueBlock.value.push(JStoASN1(input.value))
    setContainer.valueBlock.value.push(sequenceContainer)
    return setContainer
  } else if (isASN1ContextTag(input)) {
    const constructedObject = new asn1js.Constructed()
    constructedObject.idBlock.tagClass = 3 /* Context Specific */
    constructedObject.idBlock.tagNumber = input.value
    constructedObject.valueBlock.value.push(JStoASN1(input.contains))
    return constructedObject
  } else if (typeof input === 'string') {
    return new asn1js.PrintableString({ value: input })
  } else if (typeof input === 'boolean') {
    const retval = new asn1js.Boolean({ value: input })

    return retval
  }

  throw new Error(
    `Unsupported JavaScript type ${typeof input} ${JSON.stringify(input)}`,
  )
}

function ASN1toJS(input: ArrayBuffer): ASN1AnyJS {
  /**
   * Parse BER encoded data into objects
   */
  const data = asn1js.fromBER(input).result

  if (data.error) {
    throw new Error(data.error)
  }

  if (data instanceof asn1js.Sequence) {
    const retval = []
    for (const part of data.valueBlock.value) {
      retval.push(ASN1toJS(part.valueBeforeDecode))
    }

    return retval
  } else if (data instanceof asn1js.Set) {
    const sequences = data.valueBlock.value
    if (sequences.length !== 1) {
      throw new Error(
        'internal error: We only know how to handle sets with 1 sequence',
      )
    }

    const sequence = sequences[0]
    if (!(sequence instanceof asn1js.Sequence)) {
      throw new Error('internal error: Set must contain 1 sequence')
    }

    const sequenceData = sequence.valueBlock.value
    if (sequenceData.length !== 2) {
      throw new Error('internal error: Set->Sequence must contain 2 values')
    }

    const name = ASN1toJS(sequenceData[0].valueBeforeDecode)
    const value = ASN1toJS(sequenceData[1].valueBeforeDecode)

    if (!isASN1OID(name)) {
      throw new Error(
        `internal error: Set->Sequence->Name must be an OID, got ${name}`,
      )
    }

    if (typeof value !== 'string') {
      throw new Error(
        `internal error: Set->Sequence->Value must be a string, got ${value}`,
      )
    }

    const retval: ASN1Set = {
      type: 'set',
      name: name,
      value: value,
    }

    return retval
  } else if (data instanceof asn1js.Integer) {
    return jsIntegerToBigInt(data)
  } else if (
    data instanceof asn1js.GeneralizedTime ||
    data instanceof asn1js.UTCTime
  ) {
    return data.toDate()
  } else if (data instanceof asn1js.Null) {
    return null
  } else if (data instanceof asn1js.OctetString) {
    return Buffer.from(data.valueBlock.valueHex)
  } else if (data instanceof asn1js.BitString) {
    const retval: ASN1BitString = {
      type: 'bitstring',
      value: Buffer.from(data.valueBlock.valueHex),
    }

    return retval
  } else if (data instanceof asn1js.ObjectIdentifier) {
    const retval: ASN1OID = {
      type: 'oid',
      oid: oidToName(data),
    }

    return retval
  } else if (data instanceof asn1js.Boolean) {
    return data.valueBlock.value
  } else if (
    data instanceof asn1js.PrintableString ||
    data instanceof asn1js.BmpString ||
    data instanceof asn1js.CharacterString ||
    data instanceof asn1js.IA5String ||
    data instanceof asn1js.GeneralString ||
    data instanceof asn1js.GraphicString
  ) {
    return data.valueBlock.value
  } else if (data instanceof asn1js.Constructed) {
    if (data.idBlock.tagClass === 3 /* Context-Specific */) {
      if (data.valueBlock.value.length !== 1) {
        throw new Error(
          'internal error: Constructed values may only contain 1 value',
        )
      }

      const retval: ASN1ContextTag = {
        type: 'context',
        value: data.idBlock.tagNumber,
        contains: ASN1toJS(data.valueBlock.value[0].valueBeforeDecode),
      }

      return retval
    }
  }

  let typeName = '<unknown>'
  if (data.constructor?.name) {
    typeName = data.constructor.name
  }

  let stringRep
  try {
    stringRep = JSON.stringify(data)
  } catch (_ignored_stringify_error) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-base-to-string
      stringRep = data.toString()
    } catch (_ignored_toString_error) {
      /* Ignored error */
    }
  }

  throw new Error(
    `Unsupported ASN.1 type ${typeof data} ${typeName} ${stringRep}`,
  )
}

async function run() {
  // eslint-disable-next-line no-unused-vars, @typescript-eslint/no-unused-vars
  const TEST_BLOCK_BASE64 =
    'MIHWAgEAAgIByAIBexgTMjAyMjA2MjIxODE4MDAuMjEwWgQiAALE/SPerrujysUeJZetilu60VeOZ29M3vyUsjGPdqagsgQguP6a3fMrNmLVzXptmUh0I8Otu5S3fX4PWWBDbWxEd+IwLDAqAgEABCIAA8GUaJ5YXCd7B46iRMLXMtmmPOW5v3MD2DK+so3K1BuRAgEKAkEA66ba0QK07zVrshYkOF3cOaW61T1ckn9QymeSBE+yE7EJPDnrN6g54KxBaAjRVFlT3iZe4qTtQfXRoCkhoCgzqg=='
  const TEST_BLOCK_ASN1 = new Uint8Array([
    0x30, 0x81, 0xd6, 0x02, 0x01, 0x00, 0x02, 0x02, 0x01, 0xc8, 0x02, 0x01,
    0x7b, 0x18, 0x13, 0x32, 0x30, 0x32, 0x32, 0x30, 0x36, 0x32, 0x32, 0x31,
    0x38, 0x31, 0x38, 0x30, 0x30, 0x2e, 0x32, 0x31, 0x30, 0x5a, 0x04, 0x22,
    0x00, 0x02, 0xc4, 0xfd, 0x23, 0xde, 0xae, 0xbb, 0xa3, 0xca, 0xc5, 0x1e,
    0x25, 0x97, 0xad, 0x8a, 0x5b, 0xba, 0xd1, 0x57, 0x8e, 0x67, 0x6f, 0x4c,
    0xde, 0xfc, 0x94, 0xb2, 0x31, 0x8f, 0x76, 0xa6, 0xa0, 0xb2, 0x04, 0x20,
    0xb8, 0xfe, 0x9a, 0xdd, 0xf3, 0x2b, 0x36, 0x62, 0xd5, 0xcd, 0x7a, 0x6d,
    0x99, 0x48, 0x74, 0x23, 0xc3, 0xad, 0xbb, 0x94, 0xb7, 0x7d, 0x7e, 0x0f,
    0x59, 0x60, 0x43, 0x6d, 0x6c, 0x44, 0x77, 0xe2, 0x30, 0x2c, 0x30, 0x2a,
    0x02, 0x01, 0x00, 0x04, 0x22, 0x00, 0x03, 0xc1, 0x94, 0x68, 0x9e, 0x58,
    0x5c, 0x27, 0x7b, 0x07, 0x8e, 0xa2, 0x44, 0xc2, 0xd7, 0x32, 0xd9, 0xa6,
    0x3c, 0xe5, 0xb9, 0xbf, 0x73, 0x03, 0xd8, 0x32, 0xbe, 0xb2, 0x8d, 0xca,
    0xd4, 0x1b, 0x91, 0x02, 0x01, 0x0a, 0x02, 0x41, 0x00, 0xeb, 0xa6, 0xda,
    0xd1, 0x02, 0xb4, 0xef, 0x35, 0x6b, 0xb2, 0x16, 0x24, 0x38, 0x5d, 0xdc,
    0x39, 0xa5, 0xba, 0xd5, 0x3d, 0x5c, 0x92, 0x7f, 0x50, 0xca, 0x67, 0x92,
    0x04, 0x4f, 0xb2, 0x13, 0xb1, 0x09, 0x3c, 0x39, 0xeb, 0x37, 0xa8, 0x39,
    0xe0, 0xac, 0x41, 0x68, 0x08, 0xd1, 0x54, 0x59, 0x53, 0xde, 0x26, 0x5e,
    0xe2, 0xa4, 0xed, 0x41, 0xf5, 0xd1, 0xa0, 0x29, 0x21, 0xa0, 0x28, 0x33,
    0xaa,
  ]).buffer

  const TEST_DATA = [
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

  await b.suite(
    'Encode/Decode Block from Buffer',

    b.add('Rust ASN1toJS - JStoASN1 Test Block', () => {
      lib.JStoASN1(lib.ASN1toJS(TEST_BLOCK_ASN1)).toBER()
    }),

    b.add('JavaScript ASN1toJS - JStoASN1 Test Block', () => {
      JStoASN1(ASN1toJS(TEST_BLOCK_ASN1)).toBER()
    }),

    b.cycle(),
    b.complete(),
  )

  await b.suite(
    'Encode/Decode Test Data',

    b.add('Rust JStoASN1 - ASN1toJS Test Sequence', () => {
      lib.ASN1toJS(lib.JStoASN1(TEST_DATA).toBER())
    }),

    b.add('JavaScript JStoASN1 - ASN1toJS Test Sequence', () => {
      ASN1toJS(JStoASN1(TEST_DATA).toBER())
    }),

    b.cycle(),
    b.complete(),
  )

  await b.suite(
    'Encode/Decode Block from Base64',

    b.add('Rust ASN1toJS Test Block', () => {
      const asn1 = lib.ASN1Decoder.fromBase64(TEST_BLOCK_BASE64)
      asn1.intoArray()
    }),

    b.add('JavaScript ASN1toJS Test Block', () => {
      const buffer = Uint8Array.from(
        Buffer.from(TEST_BLOCK_BASE64, 'base64'),
      ).buffer
      ASN1toJS(buffer)
    }),

    b.cycle(),
    b.complete(),
  )
}

run().catch((e) => {
  console.error(e)
})

import * as asn1js from 'asn1js'

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

export function BigIntToBuffer(value: bigint): Buffer {
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

export function JStoASN1(input: ASN1AnyJS): ASN1AnyASN {
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

export function ASN1toJS(input: ArrayBuffer): ASN1AnyJS {
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

import test from 'ava'

import * as lib from '..'

/* Wrap an INTEGER in `depth` definite-length SEQUENCEs */
function nestedSequences(depth: number): Buffer {
  let data = Buffer.from([0x02, 0x01, 0x01])
  for (let i = 0; i < depth; i++) {
    const length = data.length
    let header: Buffer
    if (length < 0x80) {
      header = Buffer.from([0x30, length])
    } else {
      header = Buffer.alloc(6)
      header[0] = 0x30
      header[1] = 0x84
      header.writeUInt32BE(length, 2)
    }
    data = Buffer.concat([header, data])
  }
  return data
}

function unwrap(value: unknown, depth: number): unknown {
  for (let i = 0; i < depth; i++) {
    if (!Array.isArray(value)) {
      throw new Error(`not an array at depth ${i}`)
    }
    value = value[0]
  }
  return value
}

test('decodes data nested up to the limit', (t) => {
  const data = nestedSequences(128)

  t.is(unwrap(lib.ASN1toJS(data), 128), 1n)
  t.is(unwrap(lib.ASN1toJS(data.toString('base64')), 128), 1n)
  t.is(unwrap(new lib.ASN1Decoder(data).intoArray(), 128), 1n)
})

test('rejects data nested past the limit', (t) => {
  const data = nestedSequences(129)
  const expected = { message: 'The provided ASN1 data is nested too deeply' }

  t.throws(() => lib.ASN1toJS(data), expected)
  t.throws(() => lib.ASN1toJS(data.toString('base64')), expected)
  t.throws(() => lib.ASN1toJS(data.toString('hex')), expected)
  t.throws(() => new lib.ASN1Decoder(data), expected)
  t.throws(() => lib.ASN1Decoder.fromBuffer(data), expected)
  t.throws(() => lib.ASN1Decoder.fromBase64(data.toString('base64')), expected)
  t.throws(() => lib.ASN1Decoder.fromHex(data.toString('hex')), expected)
})

test('rejects very deeply nested data', (t) => {
  const data = nestedSequences(100_000)

  t.throws(() => lib.ASN1toJS(data), {
    message: 'The provided ASN1 data is nested too deeply',
  })
})

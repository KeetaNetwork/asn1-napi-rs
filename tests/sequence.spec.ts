import test from 'ava'

import * as lib from '..'

const TEST_SEQUENCES: any[] = [
	[1n, 2n, 3n, 4n, 5n],
	[
		1n,
		'test',
		{ type: 'oid', oid: 'commonName' },
		{ type: 'set', name: { type: 'oid', oid: 'commonName' }, value: 'test' },
		532434n,
	],
]

const TEST_SEQUENCES_ASN1 = [
	new Uint8Array([
		0x30, 0x0f, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03, 0x02,
		0x01, 0x04, 0x02, 0x01, 0x05,
	]).buffer,
	new Uint8Array([
		0x30, 0x22, 0x02, 0x01, 0x01, 0x13, 0x04, 0x74, 0x65, 0x73, 0x74, 0x06,
		0x03, 0x55, 0x04, 0x03, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04,
		0x03, 0x13, 0x04, 0x74, 0x65, 0x73, 0x74, 0x02, 0x03, 0x08, 0x1f, 0xd2,
	]).buffer,
]

test('JS ASN1Set to ASN1 conversion', (t) => {
	TEST_SEQUENCES.forEach((v, i) => {
		t.deepEqual(lib.JStoASN1(v).toBER(), TEST_SEQUENCES_ASN1[i])
	})
})

test('ASN1 to Js ASN1Set conversion from byte code', (t) => {
	TEST_SEQUENCES_ASN1.forEach((v, i) => {
		const data = new Uint8Array(v)
		const obj = new lib.ASN1Decoder(Array.from(data))

		t.deepEqual(obj.intoArray(), TEST_SEQUENCES[i])
		t.deepEqual(lib.ASN1toJS(v), TEST_SEQUENCES[i])
	})
})

test('ASN1 to Js typed array conversion from base64', (t) => {
	const input = [1n, 2n, 3n, 4n, 5n]
	const obj = lib.ASN1Decoder.fromBase64('MA8CAQECAQICAQMCAQQCAQU=')

	t.deepEqual(obj.intoArray(), input)
})

test('ASN1 to Js mixed array conversion from base64', (t) => {
	const oid: lib.ASN1OID = { type: 'oid', oid: 'commonName' }
	const set: lib.ASN1Set = { type: 'set', name: oid, value: 'test' }
	const input = [1n, 'test', oid, set, 532434n]
	const obj = lib.ASN1Decoder.fromBase64(
		'MCICAQETBHRlc3QGA1UEAzENMAsGA1UEAxMEdGVzdAIDCB/S',
	)

	t.deepEqual(obj.intoArray(), input)
})

test('ASN1 to Js mixed array conversion round trip', (t) => {
	TEST_SEQUENCES_ASN1.forEach((v, i) => {
		const js = new lib.ASN1Decoder(v)

		t.deepEqual(js.intoArray(), TEST_SEQUENCES[i])
		t.deepEqual(lib.JStoASN1(lib.ASN1toJS(v)).toBER(), TEST_SEQUENCES_ASN1[i])
	})
})

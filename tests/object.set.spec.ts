import test from 'ava'

import * as lib from '..'

const TEST_SETS: lib.ASN1Set[] = [
	{ type: 'set', name: { type: 'oid', oid: 'commonName' }, value: 'test' },
]

const TEST_SETS_ASN1 = [
	new Uint8Array([
		0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x04, 0x74,
		0x65, 0x73, 0x74,
	]).buffer,
]

test('JS ASN1Set to ASN1 conversion', (t) => {
	TEST_SETS.forEach((v, i) => {
		t.deepEqual(lib.JStoASN1(v).toBER(), TEST_SETS_ASN1[i])
	})
})

test('ASN1 to Js ASN1Set conversion from byte code', (t) => {
	TEST_SETS_ASN1.forEach((v, i) => {
		const data = new Uint8Array(v)
		const obj = new lib.ASN1Decoder(Array.from(data))

		t.deepEqual(obj.intoSet(), TEST_SETS[i])
		t.deepEqual(lib.ASN1toJS(v), TEST_SETS[i])
	})
})

test('ASN1 to Js ASN1Set conversion from base64', (t) => {
	const oid: lib.ASN1OID = { type: 'oid', oid: 'commonName' }
	const set: lib.ASN1Set = { type: 'set', name: oid, value: 'test' }
	const obj = lib.ASN1Decoder.fromBase64('MQ0wCwYDVQQDEwR0ZXN0')

	t.deepEqual(obj.intoSet(), set)
})

test('ASN1 to Js ASN1Set conversion round trip', (t) => {
	TEST_SETS_ASN1.forEach((v, i) => {
		const js = new lib.ASN1Decoder(v)

		t.deepEqual(js.intoSet(), TEST_SETS[i])
		t.deepEqual(lib.JStoASN1(lib.ASN1toJS(v)).toBER(), TEST_SETS_ASN1[i])
	})
})

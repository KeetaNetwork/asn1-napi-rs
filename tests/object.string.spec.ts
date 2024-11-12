
import test from 'ava';

import * as lib from '..';

const TEST_STRINGS: { in: lib.ASN1String; out?: string }[] = [
    { in: { type: 'string', value: 'Test', kind: 'printable' }, out: 'Test' },
	{ in: { type: 'string', value: 'Test', kind: 'ia5' } },
	{ in: { type: 'string', value: 'Test_', kind: 'ia5' }, out: 'Test_' },
	{ in: { type: 'string', value: 'Test', kind: 'utf8' } },
	{ in: { type: 'string', value: 'Tes\u1133', kind: 'utf8' }, out: 'Tes\u1133' },
]

const TEST_STRINGS_ASN1 = [
    new Uint8Array([0x13, 0x4, 0x54, 0x65, 0x73, 0x74]).buffer,
    new Uint8Array([0x16, 0x4, 0x54, 0x65, 0x73, 0x74]).buffer,
    new Uint8Array([0x16, 0x5, 0x54, 0x65, 0x73, 0x74, 0x5f]).buffer,
    new Uint8Array([0xc, 0x4, 0x54, 0x65, 0x73, 0x74]).buffer,
    new Uint8Array([0xc, 0x6, 0x54, 0x65, 0x73, 0xe1, 0x84, 0xb3]).buffer,
]

test('JS ASN1String to ASN1 conversion', (t) => {
	TEST_STRINGS.forEach((v, i) => {
        t.deepEqual(lib.JStoASN1(v.in).toBER(), TEST_STRINGS_ASN1[i])
	})
})

test('ASN1 to Js ASN1String conversion from byte code', (t) => {
	TEST_STRINGS_ASN1.forEach((v, i) => {
        const obj = new lib.ASN1Decoder(v)
		t.deepEqual(obj.intoString(), TEST_STRINGS[i].out ?? TEST_STRINGS[i].in.value)
		t.deepEqual(lib.ASN1toJS(v), TEST_STRINGS[i].out ?? TEST_STRINGS[i].in)
	})
})

test('ASN1 to ASN1String conversion from base64', (t) => {
	const obj = lib.ASN1Decoder.fromBase64(
		'DAZUZXPhhLM=',
	)

	t.deepEqual(obj.intoString(), 'Tes\u1133')
})

test('ASN1 to Js ANS1String conversion round trip', (t) => {
	TEST_STRINGS_ASN1.forEach((v, i) => {
        t.deepEqual(lib.JStoASN1(lib.ASN1toJS(v)).toBER(), TEST_STRINGS_ASN1[i])
	})
})


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
        // const obj = new lib.ASN1Decoder(v)
		// t.deepEqual(obj.intoString(), TEST_STRINGS[i].out ?? TEST_STRINGS[i].in.value)
		t.deepEqual(lib.ASN1toJS(v), TEST_STRINGS[i].out ?? TEST_STRINGS[i].in)
	})
})

// test('ASN1 to ASN1String conversion from base64', (t) => {
// 	const obj = lib.ASN1Decoder.fromBase64(
// 		'A0cAMEQCIHmXWc+ASZ/3agYiWczwPR7JkRbJSAdL26s0/YPyHb0/AiBUOWxP9BGZG9oPX6LEaJ3WNQjqCF/Yk69p3x37srdqAA==',
// 	)

// 	t.deepEqual(obj.intoBitString(), {
// 		type: 'bitstring',
// 		value: Buffer.from(
// 			new Uint8Array([
// 				0x30, 0x44, 0x02, 0x20, 0x79, 0x97, 0x59, 0xcf, 0x80, 0x49, 0x9f, 0xf7,
// 				0x6a, 0x06, 0x22, 0x59, 0xcc, 0xf0, 0x3d, 0x1e, 0xc9, 0x91, 0x16, 0xc9,
// 				0x48, 0x07, 0x4b, 0xdb, 0xab, 0x34, 0xfd, 0x83, 0xf2, 0x1d, 0xbd, 0x3f,
// 				0x02, 0x20, 0x54, 0x39, 0x6c, 0x4f, 0xf4, 0x11, 0x99, 0x1b, 0xda, 0x0f,
// 				0x5f, 0xa2, 0xc4, 0x68, 0x9d, 0xd6, 0x35, 0x08, 0xea, 0x08, 0x5f, 0xd8,
// 				0x93, 0xaf, 0x69, 0xdf, 0x1d, 0xfb, 0xb2, 0xb7, 0x6a, 0x00,
// 			]),
// 		),
// 	})
// })

test('ASN1 to Js ANS1String conversion round trip', (t) => {
	TEST_STRINGS_ASN1.forEach((v, i) => {
        t.deepEqual(lib.JStoASN1(lib.ASN1toJS(v)).toBER(), TEST_STRINGS_ASN1[i])
	})
})

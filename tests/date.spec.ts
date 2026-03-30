
import test from 'ava';

import * as lib from '..';

// Each case pairs a JS Date with its expected DER encoding.
// `out` overrides the expected decode result when encoding is lossy (e.g. ms truncation).
// RFC 5280 §4.1.2.5.1: UTCTime (0x17) for years < 2050, GeneralizedTime (0x18) for >= 2050.
const TEST_CASES: { in: Date; out?: Date; der: ArrayBuffer }[] = [
	{
		in: new Date(0),
		der: new Uint8Array([0x17, 0x0d, 0x37, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a]).buffer,
	},
	{
		in: new Date('2022-09-26T10:00:00.000+00:00'),
		der: new Uint8Array([0x17, 0x0d, 0x32, 0x32, 0x30, 0x39, 0x32, 0x36, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a]).buffer,
	},
	{
		in: new Date('2022-09-26T10:10:32.420+00:00'),
		out: new Date('2022-09-26T10:10:32.000+00:00'),
		der: new Uint8Array([0x17, 0x0d, 0x32, 0x32, 0x30, 0x39, 0x32, 0x36, 0x31, 0x30, 0x31, 0x30, 0x33, 0x32, 0x5a]).buffer,
	},
	{
		in: new Date('2052-09-26T10:10:32.420+00:00'),
		der: new Uint8Array([0x18, 0x13, 0x32, 0x30, 0x35, 0x32, 0x30, 0x39, 0x32, 0x36, 0x31, 0x30, 0x31, 0x30, 0x33, 0x32, 0x2e, 0x34, 0x32, 0x30, 0x5a]).buffer,
	},
	// RFC 5280 pivot: UTCTime 2-digit year >= 50 → 19xx, < 50 → 20xx
	{
		in: new Date('1950-06-01T12:00:00Z'),
		der: new Uint8Array([0x17, 0x0d, 0x35, 0x30, 0x30, 0x36, 0x30, 0x31, 0x31, 0x32, 0x30, 0x30, 0x30, 0x30, 0x5a]).buffer,
	},
	{
		in: new Date('1969-01-01T00:00:00Z'),
		der: new Uint8Array([0x17, 0x0d, 0x36, 0x39, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a]).buffer,
	},
	{
		in: new Date('2049-06-01T12:00:00Z'),
		der: new Uint8Array([0x17, 0x0d, 0x34, 0x39, 0x30, 0x36, 0x30, 0x31, 0x31, 0x32, 0x30, 0x30, 0x30, 0x30, 0x5a]).buffer,
	},
]

test('JS Date to ASN1 conversion', (t) => {
	TEST_CASES.forEach((v) => {
		t.deepEqual(lib.JStoASN1(v.in).toBER(), v.der)
	})
})

test('ASN1 to Js Date conversion from byte code', (t) => {
	TEST_CASES.forEach((v) => {
		const expected = v.out ?? v.in
		t.deepEqual(new lib.ASN1Decoder(v.der).intoDate(), expected)
		t.deepEqual(lib.ASN1toJS(v.der), expected)
	})
})

test('ASN1 to Js Date conversion from base64', (t) => {
	const obj = lib.ASN1Decoder.fromBase64('GA8yMDIyMDkyNjEwMDAwMFo=')
	const date = obj.intoDate()

	t.true(date instanceof Date)
	t.deepEqual(date, new Date('2022-09-26T10:00:00.000+00:00'))
})

test('ASN1 to Js Date conversion round trip', (t) => {
	TEST_CASES.forEach((v) => {
		const expected = v.out ?? v.in
		t.deepEqual(new lib.ASN1Decoder(v.der).intoDate(), expected)
		t.deepEqual(lib.JStoASN1(lib.ASN1toJS(v.der)).toBER(), v.der)
	})
})

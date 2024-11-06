
import test from 'ava';

import * as lib from '..';

const TEST_DATES: { in: Date; out?: Date; }[] = [
	{ in: new Date(0) },
	{ in: new Date('2022-09-26T10:00:00.000+00:00') },
	{ in: new Date('2022-09-26T10:10:32.420+00:00'), out: new Date('2022-09-26T10:10:32.000+00:00') },
	{ in: new Date('2052-09-26T10:10:32.420+00:00') },
]

const TEST_DATES_ASN1 = [
	new Uint8Array([0x17, 0x0d, 0x37, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a]).buffer,
	new Uint8Array([0x17, 0x0d, 0x32, 0x32, 0x30, 0x39, 0x32, 0x36, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a]).buffer,
	new Uint8Array([0x17, 0x0d, 0x32, 0x32, 0x30, 0x39, 0x32, 0x36, 0x31, 0x30, 0x31, 0x30, 0x33, 0x32, 0x5a]).buffer,
	new Uint8Array([0x18, 0x13, 0x32, 0x30, 0x35, 0x32, 0x30, 0x39, 0x32, 0x36, 0x31, 0x30, 0x31, 0x30, 0x33, 0x32, 0x2e, 0x34, 0x32, 0x30, 0x5a]).buffer
]

test('JS Date to ASN1 conversion', (t) => {
	TEST_DATES.forEach((v, i) => {
		t.deepEqual(lib.JStoASN1(v.in).toBER(), TEST_DATES_ASN1[i])
	})
})

test('ASN1 to Js Date conversion from byte code', (t) => {
	TEST_DATES_ASN1.forEach((v, i) => {
		const obj = new lib.ASN1Decoder(v)
		const expected = TEST_DATES[i].out ?? TEST_DATES[i].in
		t.deepEqual(obj.intoDate(), expected)
		t.deepEqual(lib.ASN1toJS(v), expected)
	})
})

test('ASN1 to Js Date conversion from base64', (t) => {
	const obj = lib.ASN1Decoder.fromBase64('GA8yMDIyMDkyNjEwMDAwMFo=')
	const date = obj.intoDate()

	t.true(date instanceof Date)
	t.deepEqual(date, new Date('2022-09-26T10:00:00.000+00:00'))
})

test('ASN1 to Js Date conversion round trip', (t) => {
	TEST_DATES_ASN1.forEach((v, i) => {
		const js = new lib.ASN1Decoder(v)

		t.deepEqual(js.intoDate(), TEST_DATES[i].out ?? TEST_DATES[i].in)
		t.deepEqual(lib.JStoASN1(lib.ASN1toJS(v)).toBER(), TEST_DATES_ASN1[i])
	})
})

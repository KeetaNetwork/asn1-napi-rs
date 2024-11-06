

import test from 'ava';

import * as lib from '..';


const TEST_DATES: { in: lib.ASN1Date; out?: Date }[] = [
    { in: { type: 'date', kind: 'utc', date: new Date(1729868125000) }, out: new Date(1729868125000) }, // 2024-10-25T14:55:25.000Z
	{ in: { type: 'date', kind: 'utc', date: new Date(1729868125001) }, out: new Date(1729868125000) }, // 2024-10-25T14:55:25.000Z
	
    { in: { type: 'date', kind: 'general', date: new Date(1729868125001) } }, // { object: 2024-10-25T14:55:25.001Z }
	{ in: { type: 'date', kind: 'general', date: new Date(2524694400001) }, out: new Date(2524694400001) }, // 2050-01-01T00:00:00.001Z
    
    { in: { type: 'date', kind: 'default', date: new Date(1729868125000) }, out: new Date(1729868125000) }, // 2024-10-25T14:55:25.000Z
	{ in: { type: 'date', kind: 'default', date: new Date(2524694400001) }, out: new Date(2524694400001) }, // 2050-01-01T00:00:00.001Z
    { in: { type: 'date', date: new Date(1729868125000) }, out: new Date(1729868125000) }, // 2024-10-25T14:55:25.000Z
	{ in: { type: 'date', date: new Date(2524694400001) }, out: new Date(2524694400001) }, // 2050-01-01T00:00:00.001Z
]

const TEST_DATES_ASN1 = [
    // UTC
    new Uint8Array([
        0x17, 0x0d, 0x32, 0x34, 0x31, 0x30, 0x32, 0x35, 0x31, 0x34,
        0x35, 0x35, 0x32, 0x35, 0x5a
    ]).buffer,
    new Uint8Array([
        0x17, 0x0d, 0x32, 0x34, 0x31, 0x30, 0x32, 0x35, 0x31, 0x34,
        0x35, 0x35, 0x32, 0x35, 0x5a
    ]).buffer,

    // GENERAL
    new Uint8Array([
        0x18, 0x13, 0x32, 0x30, 0x32, 0x34, 0x31, 0x30, 0x32, 0x35,
        0x31, 0x34, 0x35, 0x35, 0x32, 0x35, 0x2e, 0x30, 0x30, 0x31,
        0x5a,
    ]).buffer,
    new Uint8Array([
        0x18, 0x13, 0x32, 0x30, 0x35, 0x30, 0x30, 0x31, 0x30, 0x32,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2e, 0x30, 0x30, 0x31,
        0x5a,
    ]).buffer,
    
    // DEFAULT
    new Uint8Array([
        0x17, 0x0d, 0x32, 0x34, 0x31, 0x30, 0x32, 0x35, 0x31, 0x34,
        0x35, 0x35, 0x32, 0x35, 0x5a
    ]).buffer,
    new Uint8Array([
        0x18, 0x13, 0x32, 0x30, 0x35, 0x30, 0x30, 0x31, 0x30, 0x32,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2e, 0x30, 0x30, 0x31,
        0x5a,
    ]).buffer,
    new Uint8Array([
        0x17, 0x0d, 0x32, 0x34, 0x31, 0x30, 0x32, 0x35, 0x31, 0x34,
        0x35, 0x35, 0x32, 0x35, 0x5a
    ]).buffer,
    new Uint8Array([
        0x18, 0x13, 0x32, 0x30, 0x35, 0x30, 0x30, 0x31, 0x30, 0x32,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2e, 0x30, 0x30, 0x31,
        0x5a,
    ]).buffer,
]

test('JS ASN1Date to ASN1 conversion', (t) => {
	TEST_DATES.forEach((v, i) => {
        t.deepEqual(lib.JStoASN1(v.in).toBER(), TEST_DATES_ASN1[i])
    })
})

test('ASN1 to Js ASN1Date conversion from byte code', (t) => {
	TEST_DATES_ASN1.forEach((v, i) => {
        const obj = new lib.ASN1Decoder(v)
        t.deepEqual(obj.intoDate(), TEST_DATES[i].out ?? TEST_DATES[i].in.date)
		t.deepEqual(lib.ASN1toJS(v), TEST_DATES[i].out ?? TEST_DATES[i].in)
	})
})

test('ASN1 to ASN1Date conversion from base64', (t) => {
	const obj = lib.ASN1Decoder.fromBase64(
		'GBMyMDUwMDEwMjAwMDAwMC4wMDBa',
	)
	t.deepEqual(obj.intoDate(), new Date(2524694400000))
})

test('ASN1 to Js ANS1Date conversion round trip', (t) => {
    TEST_DATES_ASN1.forEach((v, i) => {
        t.deepEqual(lib.JStoASN1(lib.ASN1toJS(v)).toBER(), TEST_DATES_ASN1[i])
	})
})
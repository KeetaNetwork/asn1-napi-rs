

import test from 'ava';

import * as lib from '..';


const TEST_DATES: { in: lib.ASN1Date; out?: Date }[] = [
    { in: { type: 'date', kind: 'utc', date: new Date(1729868125000) }, out: new Date(1729868125000) },
	{ in: { type: 'date', kind: 'utc', date: new Date(1729868125001) }, out: new Date(1729868125000) },
	
    { in: { type: 'date', kind: 'general', date: new Date(1729868125001) } },
	{ in: { type: 'date', kind: 'general', date: new Date(2524694400001) }, out: new Date(2524694400001) },
    
    { in: { type: 'date', kind: 'default', date: new Date(1729868125000) }, out: new Date(1729868125000) },
	{ in: { type: 'date', kind: 'default', date: new Date(2524694400001) }, out: new Date(2524694400001) },
    { in: { type: 'date', date: new Date(1729868125000) }, out: new Date(1729868125000) },
	{ in: { type: 'date', date: new Date(2524694400001) }, out: new Date(2524694400001) },
]

const DATE_UTC_ASN1 = new Uint8Array([
    0x17, 0x0d, 0x32, 0x34, 0x31, 0x30, 0x32, 0x35, 0x31, 0x34,
    0x35, 0x35, 0x32, 0x35, 0x5a
]).buffer

const DATE_GENERAL_ASN1 = new Uint8Array([
    0x18, 0x13, 0x32, 0x30, 0x35, 0x30, 0x30, 0x31, 0x30, 0x32,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2e, 0x30, 0x30, 0x31,
    0x5a,
]).buffer

const TEST_DATES_ASN1 = [
    // UTC
    DATE_UTC_ASN1,
    DATE_UTC_ASN1,

    // GENERAL
    new Uint8Array([
        0x18, 0x13, 0x32, 0x30, 0x32, 0x34, 0x31, 0x30, 0x32, 0x35,
        0x31, 0x34, 0x35, 0x35, 0x32, 0x35, 0x2e, 0x30, 0x30, 0x31,
        0x5a,
    ]).buffer,
    DATE_GENERAL_ASN1,
    
    // DEFAULT
    DATE_UTC_ASN1,
    DATE_GENERAL_ASN1,
    DATE_UTC_ASN1,
    DATE_GENERAL_ASN1,
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
		'GBMyMDI0MTAyNTE0NTUyNS4wMDFa',
	)
	t.deepEqual(obj.intoDate(), new Date(1729868125001))
})

test('ASN1 to Js ANS1Date conversion round trip', (t) => {
    TEST_DATES_ASN1.forEach((v, i) => {
        t.deepEqual(lib.JStoASN1(lib.ASN1toJS(v)).toBER(), TEST_DATES_ASN1[i])
	})
})
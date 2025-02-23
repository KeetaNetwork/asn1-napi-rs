import test from 'ava'

import * as lib from '..'

test('Complex structure', (t) => {
	const input = [
		[
			{ type: 'context', kind: 'explicit', value: 0, contains: 2n } as lib.ASN1ContextTag,
			1n,
			[{ type: 'oid', oid: 'sha3-256WithEcDSA' } as lib.ASN1OID],
			[
				{
					type: 'set',
					name: { type: 'oid', oid: 'commonName' } as lib.ASN1OID,
					value:
						'keeta_aaaervzquo7sam2j4vrnmbwpln6dugaty37qqlduylti6pejpuu3xeohxxbupge',
				} as lib.ASN1Set,
			],
			[new Date('2022-09-26T10:10:32.000+00:00')],
			[new Date('2052-09-26T10:10:32.420+00:00')],
			[
				'Test', // kind: printable
				{ type: 'string', kind: 'ia5', value: 'Test' } as lib.ASN1String,
				{ type: 'string', kind: 'utf8', value: 'Test' } as lib.ASN1String,
				
				'Test_', // kind: ia5
				{ type: 'string', kind: 'utf8', value: 'Test_' } as lib.ASN1String,
				
				'Test\uD83D\uDE03', // kind: utf8
			],
			[
				{
					type: 'set',
					name: { type: 'oid', oid: 'serialNumber' } as lib.ASN1OID,
					value: '1',
				},
			],
			[
				[
					{ type: 'oid', oid: 'ecdsa' } as lib.ASN1OID,
					{ type: 'oid', oid: 'secp256k1' } as lib.ASN1OID,
				],
				{
					type: 'bitstring',
					value: Buffer.from(
						'xbjd90jjB56hh4ZJNd24wupOqpzfBq/ig+21XWs4SbQ=',
						'base64',
					),
					unusedBits: 0,
				} as lib.ASN1BitString,
			],
			{
				type: 'context',
				kind: 'explicit',
				value: 3,
				contains: [
					{ type: 'oid', oid: 'sha3-256WithEcDSA' } as lib.ASN1OID,
					true,
					Buffer.from('xbjd90jjB56hh4ZJNd24wupOqpzfBq/ig+21XWs4SbQ=', 'base64'),
				],
			} as lib.ASN1ContextTag,
		],
		[{ type: 'oid', oid: 'sha3-256WithEcDSA' }],
		{
			type: 'bitstring',
			value: Buffer.from(
				'xbjd90jjB56hh4ZJNd24wupOqpzfBq/ig+21XWs4SbQ=',
				'base64',
			),
			unusedBits: 0,
		} as lib.ASN1BitString,
	]

	// eslint-disable-next-line @typescript-eslint/ban-ts-comment
	// @ts-ignore XXX:TODO: FIX TYPES
	const ber = lib.JStoASN1(input).toBER()
	const data = lib.ASN1toJS(ber)

	t.deepEqual(data, input)
})

test('Node ASN1 Tests', (t) => {
	const integers = [-1, -0x7f, -0x80, -0xffffff, -0x7fffff]
	const checks = [
		BigInt(-1),
		BigInt(-0xffffff),
		BigInt(-0x7fffff),
		BigInt(0),
		BigInt(0x7f),
		BigInt(0x80),
		BigInt(
			'0x8bcbbf49c554d3f1b26e39005546b9f5910a12c5a61dc4cff707367a548264c2',
		),
		{ type: 'oid', oid: '1.2.3.4' } as lib.ASN1OID,
		{ type: 'context', kind: 'explicit', value: 3, contains: 42n } as lib.ASN1ContextTag,
		{
			type: 'bitstring',
			value: Buffer.from(
				'xbjd90jjB56hh4ZJNd24wupOqpzfBq/ig+21XWs4SbQ=',
				'base64',
			),
			unusedBits: 0,
		} as lib.ASN1BitString,
		{
			type: 'set',
			name: { type: 'oid', oid: '2.15216.1.999' },
			value: 'Test',
		} as lib.ASN1Set,
		Buffer.from('This is a Test String!\uD83D\uDE03'),
		'This is a Test String!',
		'This is a Test String!\uD83D\uDE03',
		new Date(0),
		new Date('2022-09-26T10:10:32.000+00:00'),
		new Date('2052-09-26T10:10:32.420+00:00'),
		
		// Match tests from node library using ASN1.js
		// new Date(),
		new Date(1729533771000),
		new Date(2524608000001),

		'Test', // kind: printable
		{ type: 'string', kind: 'ia5', value: 'Test' } as lib.ASN1String,
		{ type: 'string', kind: 'utf8', value: 'Test' } as lib.ASN1String,
		
		'Test_', // kind: ia5
		{ type: 'string', kind: 'utf8', value: 'Test_' } as lib.ASN1String,
		
		'Test\uD83D\uDE03', // kind: utf8
		
		true,
		false,
		null,
		{
			type: 'context',
			kind: 'explicit',
			value: 5,
			contains: [
				{
					type: 'set',
					name: { type: 'oid', oid: '2.15216.1.999' },
					value: 'Test',
				},
				100n,
			],
		} as lib.ASN1ContextTag,
		{
			type: 'context',
			kind: 'implicit',
			value: 5,
			contains: new Uint8Array([0x54, 0x65, 0x73, 0x74]).buffer
		} as lib.ASN1ContextTag,
	];

	const workingDate = new Date(60000);

	const nonCanonicalChecks = [
		{
			in: {
				type: 'context',
				kind: 'implicit',
				value: 5,
				contains: 'Test',
			} as lib.ASN1ContextTag,
			out: {
				type: 'context',
				kind: 'implicit',
				value: 5,
				contains: new Uint8Array([0x54, 0x65, 0x73, 0x74]).buffer
			} as lib.ASN1ContextTag,
		},
		{
			in: {
				type: 'context',
				kind: 'implicit',
				value: 5,
				contains: 10,
			} as lib.ASN1ContextTag,
			out: {
				type: 'context',
				kind: 'implicit',
				value: 5,
				contains: new Uint8Array([0x0A]).buffer
			} as lib.ASN1ContextTag,
		},
		{
			in: {
				type: 'context',
				kind: 'implicit',
				value: 5,
				contains: workingDate,
			} as lib.ASN1ContextTag,
			out: {
				type: 'context',
				kind: 'implicit',
				value: 5,
				contains: new Uint8Array([0x37, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x31, 0x30, 0x30, 0x5a]).buffer
			} as lib.ASN1ContextTag,
		},
		{
			in: {
				type: 'context',
				kind: 'implicit',
				value: 5,
				contains: new Array(1000).fill(0).map(() => workingDate)
			} as lib.ASN1ContextTag,
			out: {
				type: 'context',
				kind: 'implicit',
				value: 5,
				contains: new Uint8Array(new Array(1000).fill(0).map(() => [0x17, 0x0d, 0x37, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x31, 0x30, 0x30, 0x5a]).flat()).buffer
			} as lib.ASN1ContextTag,
		}
	];

	checks.map((v) => {
		t.deepEqual(lib.ASN1toJS(lib.JStoASN1(v).toBER()), v)
	});

	integers.map((v) => {
		t.deepEqual(lib.ASN1toJS(lib.JStoASN1(v).toBER()), BigInt(v))
	});

	nonCanonicalChecks.map((v) => {
		t.deepEqual(lib.ASN1toJS(lib.JStoASN1(v.in).toBER()), v.out)
	});

	const asn1 = lib.JStoASN1(checks)
	const js = new lib.ASN1Decoder(asn1.toBER())

	t.deepEqual(js.intoArray(), checks)
	t.deepEqual(lib.ASN1toJS(asn1.toBER()), checks)

	/**
	 * JStoASN1 with undefined should throw an error
	 */
	t.throws(function() {
		lib.JStoASN1(undefined);
	});

	/**
	 * ... unless "allowUndefined" is set to true
	 */
	t.is(lib.JStoASN1(undefined, true), undefined);

	/**
	 * An array with an element containing undefined should be elided
	 */
	const arrayCheck = lib.ASN1toJS(lib.JStoASN1(['Test', undefined]).toBER());
	t.deepEqual(arrayCheck, ['Test']);
})

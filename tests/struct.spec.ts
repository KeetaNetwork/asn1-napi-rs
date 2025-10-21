import test from 'ava'

import * as lib from '..'

type StructScenario = {
	readonly description: string
	readonly input: lib.ASN1Struct
	readonly normalized: lib.ASN1Struct
	readonly expected: ArrayBuffer
}

const STRUCT_CASES: StructScenario[] = [
	{
		description: 'struct with optional integer present',
		input: {
			type: 'struct',
			contains: { a: 1n, b: 'Test' },
		},
		normalized: {
			type: 'struct',
			fieldNames: ['a', 'b'],
			contains: { a: 1n, b: 'Test' },
		},
		expected: new Uint8Array([
			0x30, 0x09, 0x02, 0x01, 0x01, 0x13, 0x04, 0x54, 0x65, 0x73, 0x74,
		]).buffer,
	},
	{
		description: 'struct with only the required string field',
		input: {
			type: 'struct',
			contains: { b: 'Test' },
		},
		normalized: {
			type: 'struct',
			fieldNames: ['a', 'b'],
			contains: { b: 'Test' },
		},
		expected: new Uint8Array([0x30, 0x06, 0x13, 0x04, 0x54, 0x65, 0x73, 0x74]).buffer,
	},
	{
		description: 'struct already containing field names and both fields',
		input: {
			type: 'struct',
			fieldNames: ['a', 'b'],
			contains: { a: 1n, b: 'Test' },
		},
		normalized: {
			type: 'struct',
			fieldNames: ['a', 'b'],
			contains: { a: 1n, b: 'Test' },
		},
		expected: new Uint8Array([
			0x30, 0x09, 0x02, 0x01, 0x01, 0x13, 0x04, 0x54, 0x65, 0x73, 0x74,
		]).buffer,
	},
	{
		description: 'struct already containing field names and only required field',
		input: {
			type: 'struct',
			fieldNames: ['a', 'b'],
			contains: { b: 'Test' },
		},
		normalized: {
			type: 'struct',
			fieldNames: ['a', 'b'],
			contains: { b: 'Test' },
		},
		expected: new Uint8Array([0x30, 0x06, 0x13, 0x04, 0x54, 0x65, 0x73, 0x74]).buffer,
	},
]

const STRUCT_IN_CONTEXT_CASES: Array<{
	readonly input: lib.ASN1ContextTag
	readonly normalized: lib.ASN1ContextTag
	readonly expected: ArrayBuffer
}> = [
	{
		input: {
			type: 'context',
			kind: 'implicit',
			value: 3,
			contains: {
				type: 'struct',
				contains: { a: 1n, b: 'Test' },
			},
		},
		normalized: {
			type: 'context',
			kind: 'implicit',
			value: 3,
			contains: {
				type: 'struct',
				fieldNames: ['a', 'b'],
				contains: { a: 1n, b: 'Test' },
			},
		},
		expected: new Uint8Array([
			0x83, 0x09, 0x02, 0x01, 0x01, 0x13, 0x04, 0x54, 0x65, 0x73, 0x74,
		]).buffer,
	},
]

test('JS ASN1Struct to ASN1 conversion matches schema-driven expectations', (t) => {
	STRUCT_CASES.forEach(({ description, normalized, expected }) => {
		t.deepEqual(lib.JStoASN1(normalized).toBER(), expected, description)
	})
})

test('JS ASN1Struct context tag encoding matches schema-driven expectations', (t) => {
	STRUCT_IN_CONTEXT_CASES.forEach(({ normalized, expected }) => {
		t.deepEqual(lib.JStoASN1(normalized).toBER(), expected)
	})
})

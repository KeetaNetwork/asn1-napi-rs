import test from 'ava'

import * as lib from '..'

test('Error handling', (t) => {
	const js = new lib.ASN1Decoder(Buffer.from('Never gonna give you up'))

	t.throws(js.intoString)
})

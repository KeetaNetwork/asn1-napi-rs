import test from 'ava'

import * as lib from '../index'

test('Error handling', (t) => {
  const js = new lib.Asn1(Buffer.from('Never gonna give you up'))

  t.throws(js.intoString)
})

use anyhow::{bail, Error, Result};
use chrono::{DateTime, Utc};
use napi::{
	bindgen_prelude::{Array, Buffer},
	Env, JsArrayBuffer, JsBigInt, JsUnknown,
};
use num_bigint::BigInt;
use rasn::{
	ber::{decode, encode},
	types::{
		Any, BitString, BmpString, Class, GeneralString, Ia5String, NumericString, OctetString,
		PrintableString, UniversalString, Utf8String, VisibleString,
	},
	Decode, Tag,
};

use crate::{
	get_js_array_from_asn_iter, get_js_big_int_from_big_int, get_js_context_tag_from_asn1_context,
	objects::{
		ASN1BitString, ASN1Context, ASN1ContextTag, ASN1Object, ASN1RawBitString, ASN1Set, ASN1OID,
	},
	types::{ASN1Data, JsType},
	utils::{get_utc_date_time_from_asn1_milli, get_vec_from_js_unknown},
	ASN1NAPIError,
};

/// Convert ASN1 BER encoded data to JS native types. This is the main decoder
/// class for decoding ASN1 encoded data.
#[napi(js_name = "ASN1Decoder")]
#[derive(Eq, Clone, PartialEq, Debug)]
pub struct ASN1Decoder {
	tag: Tag,
	js_type: JsType,
	data: Vec<u8>,
}

/// Convert ASN1Data into ASN1 encoded data. This is the main encoder
/// class for encoding to ASN1 encoded data.
#[napi(js_name = "ASN1Encoder")]
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ASN1Encoder(ASN1Data);

/// ASN1 Iterator for sequences. Sequences use lazy loading iterators allowing
/// for chaining of operations while only executing on a consumer ensuring
/// O(n) operations.
#[napi(js_name = "ASN1Iterator")]
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ASN1Iterator {
	sequence: Vec<Any>,
	length: usize,
	index: usize,
}

#[napi]
impl ASN1Iterator {
	#[napi]
	pub fn len(&self) -> usize {
		self.length
	}
}

#[napi]
impl ASN1Encoder {
	/// Create a new ASN1Encoder instance from any ASN1 encodable type.
	#[napi(constructor)]
	pub fn js_new(
		#[napi(
			ts_arg_type = "BigInt | bigint | number | Date | ArrayBufferLike | Buffer | ASN1OID | ASN1Set | ASN1String | ASN1Date | ASN1ContextTag | ASN1BitString | string | boolean | any[] | null"
		)]
		data: JsUnknown,
	) -> Result<Self> {
		Ok(Self(ASN1Data::try_from(data)?))
	}

	/// Create a new ANS1toJS instance from ASN1Data.
	pub fn new(data: ASN1Data) -> Self {
		Self(data)
	}

	/// Encode ASN1Data to a Vec<u8> of ASN.1 encoded data.
	pub(crate) fn encode(&self) -> Result<Vec<u8>> {
		match encode(&self.0) {
			Ok(data) => Ok(data),
			Err(_) => bail!(ASN1NAPIError::InvalidDataEncoding),
		}
	}

	/// Encode the ASN.1 data as an array buffer.
	#[allow(unused_variables)]
	#[napi(js_name = "toBER", ts_return_type = "ArrayBuffer")]
	pub fn to_ber(&self, env: Env, size_only: Option<bool>) -> Result<JsArrayBuffer> {
		Ok(env.create_arraybuffer_with_data(self.encode()?)?.into_raw())
	}

	/// Encode the ASN.1 data to a ASN.1 encoded base64 encoded string.
	#[napi(js_name = "toBase64")]
	pub fn to_base64(&self) -> Result<String> {
		Ok(base64::encode(self.encode()?))
	}
}

#[napi]
impl ASN1Decoder {
	/// JS constructor.
	#[napi(constructor)]
	pub fn js_new(
		#[napi(ts_arg_type = "string | null | number[] | Buffer | ArrayBuffer")] data: JsUnknown,
	) -> Result<Self> {
		Ok(Self::new(get_vec_from_js_unknown(data)?))
	}

	/// Create a new ASN1Decoder instance from ASN1 encoded data.
	pub fn new(data: Vec<u8>) -> Self {
		// Match constructed Sequence/Set tag
		let bit = match *data.first().unwrap_or(&0x5) as u32 {
			0x30 => 0x10,
			0x31 => 0x11,
			n => n,
		};

		// ASN1 Contexts range from 0xa0 to 0xbf
		let tag = if (0xa0..=0xbf).contains(&bit) {
			Tag::new(Class::Context, bit ^ 0xa0)
		} else {
			Tag::new(Class::Universal, bit)
		};

		ASN1Decoder {
			js_type: JsType::from(tag),
			tag,
			data,
		}
	}

	/// Get the JsType of the encoded data.
	pub fn get_js_type(&self) -> &JsType {
		&self.js_type
	}

	/// Get the Tag of the encoded data.
	pub fn get_tag(&self) -> &Tag {
		&self.tag
	}

	/// Get the raw ASN.1 data.
	pub fn get_raw(&self) -> &[u8] {
		&self.data
	}

	/// Create an instance of ANS1 from a buffer.
	#[napi]
	pub fn from_buffer(value: Buffer) -> Result<ASN1Decoder> {
		Self::try_from(Vec::<u8>::from(value))
	}

	/// Create an instance of ANS1 from Base64 encoded data.
	#[napi]
	pub fn from_base64(value: String) -> Result<ASN1Decoder> {
		match base64::decode(value) {
			Ok(result) => Self::try_from(result.as_slice()),
			Err(_) => bail!(ASN1NAPIError::UnknownStringFormat),
		}
	}

	/// Create an instance of ANS1 from hex encoded data.
	#[napi]
	pub fn from_hex(value: String) -> Result<ASN1Decoder> {
		match hex::decode(value) {
			Ok(result) => Self::try_from(result.as_slice()),
			Err(_) => bail!(ASN1NAPIError::UnknownStringFormat),
		}
	}

	/// Decode ASN1 encoded data.
	pub(crate) fn decode<T: Decode>(&self) -> Result<T> {
		match decode(&self.data) {
			Ok(data) => Ok(data),
			Err(_) => bail!(ASN1NAPIError::MalformedData),
		}
	}

	/// Get a ASN1BitString object.
	pub(crate) fn get_raw_bit_string(&self) -> Result<ASN1RawBitString> {
		self.decode::<ASN1RawBitString>()
	}

	/// Get a Context object.
	pub(crate) fn get_context(&self) -> Result<ASN1Context> {
		self.decode::<ASN1Context>()
	}

	/// Decode into Any.
	pub(crate) fn into_any(self) -> Result<Any> {
		self.decode::<Any>()
	}

	/// Decode an object to an ASN1Object.
	pub(crate) fn into_object(self) -> Result<ASN1Object> {
		self.decode::<ASN1Object>()
	}

	/// Convert to a big integer.
	pub(crate) fn into_big_integer(self) -> Result<BigInt> {
		self.decode::<BigInt>()
	}

	/// Convert to an integer.
	#[napi]
	pub fn into_integer(&self) -> Result<i64> {
		self.decode::<i64>()
	}

	/// Convert to a JS big integer.
	#[napi]
	pub fn into_big_int(&self, env: Env) -> Result<JsBigInt> {
		get_js_big_int_from_big_int(env, self.decode::<BigInt>()?)
	}

	/// Convert to a boolean.
	#[napi]
	pub fn into_bool(&self) -> Result<bool> {
		self.decode::<bool>()
	}

	/// Convert to a string.
	#[napi]
	pub fn into_string(&self) -> Result<String> {
		Ok(match *self.get_tag() {
			Tag::PRINTABLE_STRING => self.decode::<PrintableString>()?.as_str().into(),
			Tag::BMP_STRING => self.decode::<BmpString>()?.as_str().into(),
			Tag::GENERAL_STRING => self.decode::<GeneralString>()?.as_str().into(),
			Tag::IA5_STRING => self.decode::<Ia5String>()?.as_str().into(),
			Tag::VISIBLE_STRING => self.decode::<VisibleString>()?.as_str().into(),
			Tag::NUMERIC_STRING => self.decode::<NumericString>()?.as_str().into(),
			Tag::UNIVERSAL_STRING => self.decode::<UniversalString>()?.as_str().into(),
			Tag::UTF8_STRING => self.decode::<Utf8String>()?.as_str().into(),
			_ => bail!(ASN1NAPIError::UnknownStringFormat),
		})
	}

	/// Convert to a date.
	#[napi]
	pub fn into_date(&self) -> Result<DateTime<Utc>> {
		get_utc_date_time_from_asn1_milli(&self.data)
	}

	/// Convert to an byte array.
	#[napi]
	pub fn into_bytes(&self) -> Result<Vec<u8>> {
		Ok(self.decode::<OctetString>()?.to_vec())
	}

	/// Convert to a buffer.
	#[napi]
	pub fn into_buffer(&self) -> Result<Buffer> {
		Ok(self.into_bytes()?.into())
	}

	/// Convert to an OID object.
	#[napi]
	pub fn into_oid(&self) -> Result<ASN1OID> {
		self.decode::<ASN1OID>()
	}

	/// Convert to a JS ASN1BitString object.
	#[napi]
	pub fn into_bit_string(&self, env: Env) -> Result<ASN1BitString> {
		let raw = self.get_raw_bit_string()?;
		let unused_bits = raw.unused_bits;
		Ok(ASN1BitString::new(
			env,
			BitString::from(raw).into_vec(),
			unused_bits,
		))
	}

	/// Convert to an Set object.
	#[napi]
	pub fn into_set(&self) -> Result<ASN1Set> {
		self.decode::<ASN1Set>()
	}

	/// Convert to an Context object.
	#[napi]
	pub fn into_context_tag(&self, env: Env) -> Result<ASN1ContextTag> {
		get_js_context_tag_from_asn1_context(env, self.get_context()?)
	}

	/// Convert a Sequence to an Array.
	#[napi(ts_return_type = "any[]")]
	pub fn into_array(&self, env: Env) -> Result<Array> {
		get_js_array_from_asn_iter(env, self.clone().into_iter())
	}
}

impl Iterator for ASN1Iterator {
	type Item = Result<ASN1Data>;

	fn next(&mut self) -> Option<Self::Item> {
		if let Some(item) = self.sequence.get(self.index) {
			self.index += 1;
			Some(ASN1Data::try_from(ASN1Decoder::new(item.as_bytes().into())))
		} else {
			None
		}
	}
}

impl IntoIterator for ASN1Decoder {
	type Item = Result<ASN1Data>;

	type IntoIter = ASN1Iterator;

	fn into_iter(self) -> Self::IntoIter {
		ASN1Iterator::from(self.decode::<Vec<Any>>().unwrap_or_default())
	}
}

impl From<Vec<Any>> for ASN1Iterator {
	fn from(sequence: Vec<Any>) -> Self {
		Self {
			length: sequence.len(),
			index: 0,
			sequence,
		}
	}
}

impl TryFrom<String> for ASN1Decoder {
	type Error = Error;

	fn try_from(value: String) -> Result<Self, Self::Error> {
		Self::try_from(value.as_str())
	}
}

impl<'a> TryFrom<&'a str> for ASN1Decoder {
	type Error = Error;

	/// Create an instance of ASN1Decoder from Base64 or hex encoded data.
	fn try_from(value: &'a str) -> Result<Self, Self::Error> {
		if let Ok(result) = base64::decode(value) {
			Self::try_from(result.as_slice())
		} else if let Ok(result) = hex::decode(value) {
			Self::try_from(result.as_slice())
		} else {
			bail!(ASN1NAPIError::UnknownStringFormat)
		}
	}
}

impl<'a> TryFrom<&'a [u8]> for ASN1Decoder {
	type Error = Error;

	fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
		Ok(Self::new(value.into()))
	}
}

impl TryFrom<Vec<u8>> for ASN1Decoder {
	type Error = Error;

	fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
		Self::try_from(value.as_slice())
	}
}

#[cfg(test)]
mod test {
	use std::collections::VecDeque;
	use std::str::FromStr;

	use chrono::{DateTime, FixedOffset, TimeZone, Utc};
	use num_bigint::BigInt;
	use rasn::types::BitString;

	use crate::asn1::*;
	use crate::objects::*;
	use crate::types::*;
	use crate::*;

	const TEST_VOTE: &str = "MFEGCWCGSAFlAwQCCDBEBCCb0PJlcOIUeBZH8vNeObY9pg\
	                         xw+6PUh6ku6n9k9VVYDgQge0hOYtjbsjyJqqx5m7D8iP+i\
	                         6dLBTcFsl/kwxUkaO1k=";
	const TEST_BLOCK: &str = "MIHWAgEAAgIByAIBexgTMjAyMjA2MjIxODE4MDAuMjEwW\
	                          gQiAALE/SPerrujysUeJZetilu60VeOZ29M3vyUsjGPdq\
	                          agsgQguP6a3fMrNmLVzXptmUh0I8Otu5S3fX4PWWBDbWx\
	                          Ed+IwLDAqAgEABCIAA8GUaJ5YXCd7B46iRMLXMtmmPOW5\
	                          v3MD2DK+so3K1BuRAgEKAkEA66ba0QK07zVrshYkOF3cO\
	                          aW61T1ckn9QymeSBE+yE7EJPDnrN6g54KxBaAjRVFlT3i\
	                          Ze4qTtQfXRoCkhoCgzqg==";
	const TEST_CERT: &str = "MIIB3jCCAYWgAwIBAgIBATAKBggqhkjOPQQDAjBEMQswCQ\
	                         YDVQQGEwJVUzELMAkGA1UECBMCQ0ExDjAMBgNVBAoTBUtl\
	                         ZXRhMRgwFgYDVQQDEw9ub2RlMS5rZWV0YS5jb20wHhcNMj\
	                         IxMTAzMDEyOTU4WhcNMjcwNTExMDEyOTU4WjBiMQswCQYD\
	                         VQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC0xvcy\
	                         BBbmdlbGVzMQ4wDAYDVQQKDAVLZWV0YTEgMB4GA1UEAwwX\
	                         Y2xpZW50MS5ub2RlMS5rZWV0YS5jb20wVjAQBgcqhkjOPQ\
	                         IBBgUrgQQACgNCAAQ3605beUhS+2ZGuk4OkQ2utb239l2g\
	                         kAl4tgKp1JFyujP8aNZ5Zh7nnfB64eWCOHtaGIXHYeXlYf\
	                         +rZ9KfnULdo00wSzAdBgNVHQ4EFgQUGKqtzLuSNICC4hId\
	                         Fc3a7QdIkhMwHwYDVR0jBBgwFoAUeqmWlg9mdQnXDtFiV8\
	                         uXgiCC8yswCQYDVR0TBAIwADAKBggqhkjOPQQDAgNHADBE\
	                         AiB/sWgSvLZSddTHD64sWgPDgQSnWXxjfIzcoP1W48lZng\
	                         IgazAF+38D5aIrcmtnD2YEp5i1ydiYzxKCU1RFAZf540c=";

	fn fixture_get_test_vote() -> Vec<ASN1Data> {
		vec![
			ASN1Data::Object(ASN1Object::Oid(ASN1OID::new("sha3-256"))),
			ASN1Data::Array(vec![
				ASN1Data::Bytes(
					hex::decode(
						"9bd0f26570e214781647f2f35e39b63da60c70\
						 fba3d487a92eea7f64f555580e",
					)
					.expect("hex"),
				),
				ASN1Data::Bytes(
					hex::decode(
						"7b484e62d8dbb23c89aaac799bb0fc\
						 88ffa2e9d2c14dc16c97f930c5491a3b59",
					)
					.expect("hex"),
				),
			]),
		]
	}

	fn fixture_get_test_block() -> Vec<ASN1Data> {
		vec![
			ASN1Data::Integer(0),
			ASN1Data::Integer(456),
			ASN1Data::Integer(123),
			ASN1Data::GeneralizedTime(DateTime::<FixedOffset>::from(
				Utc.timestamp_millis_opt(1655921880210).unwrap(),
			)),
			ASN1Data::Bytes(
				hex::decode(
					"0002C4FD23DEAEBBA3CAC51E2597AD8A5BBAD1578E6\
					 76F4CDEFC94B2318F76A6A0B2",
				)
				.expect("hex"),
			),
			ASN1Data::Bytes(
				hex::decode(
					"B8FE9ADDF32B3662D5CD7A6D99487423C3ADBB94B77\
					 D7E0F5960436D6C4477E2",
				)
				.expect("hex"),
			),
			ASN1Data::Array(vec![ASN1Data::Array(vec![
				ASN1Data::Integer(0),
				ASN1Data::Bytes(
					hex::decode(
						"0003C194689E585C277B078EA244C2D732D9A63CE5B9BF7\
						 303D832BEB28DCAD41B91",
					)
					.expect("hex"),
				),
				ASN1Data::Integer(10),
			])]),
			ASN1Data::BigInt(
				BigInt::from_str(
					"123420849842679662628402583993698371919475023\
					 865306400494192638014388787592329547816109951\
					 558088511082592942731994462782276923187529716\
					 58125549615746397098",
				)
				.expect("BigInt"),
			),
		]
	}

	fn fixture_get_test_cert() -> Vec<ASN1Data> {
		vec![
			ASN1Data::Array(vec![
				ASN1Data::Object(ASN1Object::Context(ASN1Context {
					value: 0,
					contains: Box::new(ASN1Data::Integer(2)),
				})),
				ASN1Data::Integer(1),
				ASN1Data::Array(vec![ASN1Data::Object(ASN1Object::Oid(ASN1OID::new(
					"sha256WithEcDSA",
				)))]),
				ASN1Data::Array(vec![
					ASN1Data::Object(ASN1Object::Set(ASN1Set::new(ASN1OID::new("2.5.4.6"), "US"))),
					ASN1Data::Object(ASN1Object::Set(ASN1Set::new(ASN1OID::new("2.5.4.8"), "CA"))),
					ASN1Data::Object(ASN1Object::Set(ASN1Set::new(
						ASN1OID::new("2.5.4.10"),
						"Keeta",
					))),
					ASN1Data::Object(ASN1Object::Set(ASN1Set::new(
						ASN1OID::new("commonName"),
						"node1.keeta.com",
					))),
				]),
				ASN1Data::Array(vec![
					ASN1Data::UtcTime(DateTime::<Utc>::from(
						Utc.with_ymd_and_hms(2022, 11, 03, 1, 29, 58).unwrap(),
					)),
					ASN1Data::UtcTime(DateTime::<Utc>::from(
						Utc.with_ymd_and_hms(2027, 05, 11, 1, 29, 58).unwrap(),
					)),
				]),
				ASN1Data::Array(vec![
					ASN1Data::Object(ASN1Object::Set(ASN1Set::new(ASN1OID::new("2.5.4.6"), "US"))),
					ASN1Data::Object(ASN1Object::Set(ASN1Set::new(ASN1OID::new("2.5.4.8"), "CA"))),
					ASN1Data::Object(ASN1Object::Set(ASN1Set::new(
						ASN1OID::new("2.5.4.7"),
						"Los Angeles",
					))),
					ASN1Data::Object(ASN1Object::Set(ASN1Set::new(
						ASN1OID::new("2.5.4.10"),
						"Keeta",
					))),
					ASN1Data::Object(ASN1Object::Set(ASN1Set::new(
						ASN1OID::new("commonName"),
						"client1.node1.keeta.com",
					))),
				]),
				ASN1Data::Array(vec![
					ASN1Data::Array(vec![
						ASN1Data::Object(ASN1Object::Oid(ASN1OID::new("ecdsa"))),
						ASN1Data::Object(ASN1Object::Oid(ASN1OID::new("secp256k1"))),
					]),
					ASN1Data::Object(ASN1Object::BitString(ASN1RawBitString::new(
						BitString::from_vec(vec![
							0x04, 0x37, 0xEB, 0x4E, 0x5B, 0x79, 0x48, 0x52, 0xFB, 0x66, 0x46, 0xBA,
							0x4E, 0x0E, 0x91, 0x0D, 0xAE, 0xB5, 0xBD, 0xB7, 0xF6, 0x5D, 0xA0, 0x90,
							0x09, 0x78, 0xB6, 0x02, 0xA9, 0xD4, 0x91, 0x72, 0xBA, 0x33, 0xFC, 0x68,
							0xD6, 0x79, 0x66, 0x1E, 0xE7, 0x9D, 0xF0, 0x7A, 0xE1, 0xE5, 0x82, 0x38,
							0x7B, 0x5A, 0x18, 0x85, 0xC7, 0x61, 0xE5, 0xE5, 0x61, 0xFF, 0xAB, 0x67,
							0xD2, 0x9F, 0x9D, 0x42, 0xDD,
						]),
						Some(0x00),
					))),
				]),
				ASN1Data::Object(ASN1Object::Context(ASN1Context::new(
					3,
					ASN1Data::Array(vec![
						ASN1Data::Array(vec![
							ASN1Data::Object(ASN1Object::Oid(ASN1OID::new("2.5.29.14"))),
							ASN1Data::Bytes(vec![
								0x04, 0x14, 0x18, 0xAA, 0xAD, 0xCC, 0xBB, 0x92, 0x34, 0x80, 0x82,
								0xE2, 0x12, 0x1D, 0x15, 0xCD, 0xDA, 0xED, 0x07, 0x48, 0x92, 0x13,
							]),
						]),
						ASN1Data::Array(vec![
							ASN1Data::Object(ASN1Object::Oid(ASN1OID::new("2.5.29.35"))),
							ASN1Data::Bytes(vec![
								0x30, 0x16, 0x80, 0x14, 0x7A, 0xA9, 0x96, 0x96, 0x0F, 0x66, 0x75,
								0x09, 0xD7, 0x0E, 0xD1, 0x62, 0x57, 0xCB, 0x97, 0x82, 0x20, 0x82,
								0xF3, 0x2B,
							]),
						]),
						ASN1Data::Array(vec![
							ASN1Data::Object(ASN1Object::Oid(ASN1OID::new("2.5.29.19"))),
							ASN1Data::Bytes(vec![0x30, 0]),
						]),
					]),
				))),
			]),
			ASN1Data::Array(vec![ASN1Data::Object(ASN1Object::Oid(ASN1OID::new(
				"sha256WithEcDSA",
			)))]),
			ASN1Data::Object(ASN1Object::BitString(ASN1RawBitString::new(
				BitString::from_vec(vec![
					0x30, 0x44, 0x02, 0x20, 0x7F, 0xB1, 0x68, 0x12, 0xBC, 0xB6, 0x52, 0x75, 0xD4,
					0xC7, 0x0F, 0xAE, 0x2C, 0x5A, 0x03, 0xC3, 0x81, 0x04, 0xA7, 0x59, 0x7C, 0x63,
					0x7C, 0x8C, 0xDC, 0xA0, 0xFD, 0x56, 0xE3, 0xC9, 0x59, 0x9E, 0x02, 0x20, 0x6B,
					0x30, 0x05, 0xFB, 0x7F, 0x03, 0xE5, 0xA2, 0x2B, 0x72, 0x6B, 0x67, 0x0F, 0x66,
					0x04, 0xA7, 0x98, 0xB5, 0xC9, 0xD8, 0x98, 0xCF, 0x12, 0x82, 0x53, 0x54, 0x45,
					0x01, 0x97, 0xF9, 0xE3, 0x47,
				]),
				Some(0x00),
			))),
		]
	}

	#[test]
	fn test_asn1_into_bool() {
		let encoded_true = "AQH/";
		let encoded_false = "AQEA";

		let obj_true = ASN1Decoder::from_base64(encoded_true.into()).expect("base64");
		let obj_false = ASN1Decoder::from_base64(encoded_false.into()).expect("base64");

		assert!(obj_true.into_bool().unwrap());
		assert!(!obj_false.into_bool().unwrap());
	}

	#[test]
	fn test_asn1_into_integer() {
		let encoded = "AgEq";
		let obj = ASN1Decoder::from_base64(encoded.into()).expect("base64");

		assert_eq!(obj.into_integer().unwrap(), 42_i64);

		let encoded = "AgP/AAE=";
		let obj = ASN1Decoder::from_base64(encoded.into()).expect("base64");

		assert_eq!(obj.into_integer().unwrap(), -65535_i64);
	}

	#[test]
	fn test_asn1_into_big_integer() {
		let encoded = "AgkBAgMEBQYHCAk=";
		let obj = ASN1Decoder::from_base64(encoded.into()).expect("base64");

		assert_eq!(
			obj.into_big_integer().unwrap(),
			BigInt::from(18591708106338011145_i128)
		);
	}

	#[test]
	fn test_asn1_into_string() {
		let encoded = "EwR0ZXN0";
		let obj = ASN1Decoder::from_base64(encoded.into()).expect("base64");

		assert_eq!(obj.into_string().unwrap(), "test");
	}

	#[test]
	fn test_asn1_into_date() {
		let encoded = "GA8yMDIyMDkyNjEwMDAwMFo=";
		let obj = ASN1Decoder::from_base64(encoded.into()).expect("base64");

		assert_eq!(
			obj.into_date().unwrap(),
			Utc.with_ymd_and_hms(2022, 9, 26, 10, 0, 0).unwrap()
		);
	}

	#[test]
	fn test_asn1_into_bytes() {
		let encoded = "BAUBAgMEBQ==";
		let obj = ASN1Decoder::from_base64(encoded.into()).expect("base64");

		assert_eq!(
			obj.into_bytes().unwrap(),
			vec![0x01, 0x02, 0x03, 0x04, 0x05]
		);
	}

	#[test]
	fn test_asn1_into_oid() {
		let encoded = "BglghkgBZQMEAgE=";
		let obj = ASN1Decoder::from_base64(encoded.into()).expect("base64");

		assert_eq!(obj.into_oid().unwrap(), ASN1OID::new("sha256"));
	}

	#[test]
	fn test_asn1_into_set() {
		let encoded = "MQ0wCwYDVQQDEwR0ZXN0";
		let obj = ASN1Decoder::from_base64(encoded.into()).expect("base64");

		assert_eq!(
			obj.into_set().unwrap(),
			ASN1Set::new(ASN1OID::new("commonName"), "test")
		);
	}

	#[test]
	fn test_asn1_into_bit_string() {
		let encoded = "AwYAChAUIAk=";
		let obj = ASN1Decoder::from_base64(encoded.into()).expect("base64");

		assert_eq!(
			BitString::from(obj.get_raw_bit_string().unwrap()),
			BitString::from_vec(vec![0xa, 0x10, 0x14, 0x20, 0x9])
		);
	}

	#[test]
	fn test_asn1_into_object() {
		let encoded = "MQ0wCwYDVQQDEwR0ZXN0";
		let obj = ASN1Decoder::from_base64(encoded.into()).expect("base64");

		assert_eq!(
			obj.into_set().unwrap(),
			ASN1Set::new(ASN1OID::new("commonName"), "test")
		);
	}

	#[test]
	fn test_asn1_into_sequence() {
		fn sum_sequence(data: Vec<u8>) -> Result<i64, Box<dyn std::error::Error>> {
			Ok(ASN1Decoder::new(data)
				.into_iter()
				.map(|result| cast_data!(result, Result::Ok))
				.map(|data| cast_data!(data, ASN1Data::Integer))
				.sum())
		}

		let data = vec![
			0x30, 0x0f, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03, 0x02, 0x01, 0x04,
			0x02, 0x01, 0x05,
		];

		assert_eq!(
			sum_sequence(data).unwrap(),
			[1, 2, 3, 4, 5].iter().sum::<i64>()
		);
	}

	#[test]
	fn test_asn1_into_context_tag() {
		let encoded = "oFMwUQYJYIZIAWUDBAIIMEQEICr/S0giG9GX2MTM\
		               rxc3EIGys5PE8jr8r18mIzZ2zYQ6BCCDoM+00VOs\
		               NOWyS0x0/VCAPCC3p6iC3JSwDdTpMH/5rw==";
		let obj = ASN1Decoder::from_base64(encoded.into()).unwrap();
		let oid = ASN1Object::Oid(ASN1OID::new("sha3-256"));

		let contents = ASN1Data::Array(vec![
			ASN1Data::Object(oid),
			ASN1Data::Array(vec![
				ASN1Data::Bytes(vec![
					0x2a, 0xff, 0x4b, 0x48, 0x22, 0x1b, 0xd1, 0x97, 0xd8, 0xc4, 0xcc, 0xaf, 0x17,
					0x37, 0x10, 0x81, 0xb2, 0xb3, 0x93, 0xc4, 0xf2, 0x3a, 0xfc, 0xaf, 0x5f, 0x26,
					0x23, 0x36, 0x76, 0xcd, 0x84, 0x3a,
				]),
				ASN1Data::Bytes(vec![
					0x83, 0xa0, 0xcf, 0xb4, 0xd1, 0x53, 0xac, 0x34, 0xe5, 0xb2, 0x4b, 0x4c, 0x74,
					0xfd, 0x50, 0x80, 0x3c, 0x20, 0xb7, 0xa7, 0xa8, 0x82, 0xdc, 0x94, 0xb0, 0x0d,
					0xd4, 0xe9, 0x30, 0x7f, 0xf9, 0xaf,
				]),
			]),
		]);

		assert_eq!(obj.get_context().unwrap(), ASN1Context::new(0, contents));
	}

	#[test]
	fn test_asn1_block_into_sequence() {
		let block = fixture_get_test_block();
		let obj = ASN1Decoder::from_base64(TEST_BLOCK.into()).expect("base64");
		let js_type = *obj.get_js_type();

		assert_eq!(js_type, JsType::Sequence);

		obj.into_iter().enumerate().for_each(|(i, data)| {
			assert_eq!(data.unwrap(), block[i]);
		});
	}

	#[test]
	fn test_asn1_vote_into_sequence() {
		let vote = fixture_get_test_vote();
		let obj = ASN1Decoder::from_base64(TEST_VOTE.into()).expect("base64");
		let js_type = *obj.get_js_type();

		assert_eq!(js_type, JsType::Sequence);

		obj.into_iter().enumerate().for_each(|(i, data)| {
			assert_eq!(data.unwrap(), vote[i]);
		});
	}

	#[test]
	fn test_asn1_cert_into_sequence() {
		let obj = ASN1Decoder::from_base64(TEST_CERT.into()).expect("base64");
		let js_type = *obj.get_js_type();

		assert_eq!(js_type, JsType::Sequence);

		let mut test = VecDeque::from(fixture_get_test_cert());
		let test_tbs = test.pop_front().unwrap();
		let test_algo = test.pop_front().unwrap();
		let test_sig = test.pop_front().unwrap();

		let mut cert = obj.into_iter();
		let tbs = cert.next().unwrap().unwrap();
		let algo = cert.next().unwrap().unwrap();
		let sig = cert.next().unwrap().unwrap();

		assert_eq!(tbs, test_tbs);
		assert_eq!(algo, test_algo);
		assert_eq!(sig, test_sig);
	}

	#[test]
	fn test_asn1_encoder_to_base64() {
		let block = fixture_get_test_block();
		let encoder = ASN1Encoder::new(ASN1Data::Array(block));

		assert_eq!(encoder.to_base64().unwrap(), TEST_BLOCK);
	}
}

use std::collections::VecDeque;

use anyhow::{bail, Error, Result};
use chrono::{DateTime, Datelike, FixedOffset, Utc};
use napi::bindgen_prelude::FromNapiValue;
use napi::{Env, JsBuffer, JsNumber, JsObject, JsString, JsUnknown, ValueType};
use rasn::{
	ber::de::DecoderOptions,
	de::Error as rasnDeError,
	enc::Error as rasnEncError,
	types::{Any, BitString, Class, ObjectIdentifier, Oid, Open},
	AsnType, Decode, Decoder, Encode, Encoder, Tag,
};

use crate::{
	constants::*,
	type_object,
	types::ASN1Data,
	utils::{
		get_buffer_from_js, get_oid_elements_from_string, get_string_from_js,
		get_string_from_oid_elements, is_ia5_string, is_printable_string,
	},
	ASN1Decoder, ASN1NAPIError,
};

/// HashMap for names to OID
static NAME_TO_OID_MAP: phf::Map<&'static str, &'static [u32]> = phf_map! {
	"sha256" => &[2, 16, 840, 1, 101, 3, 4, 2, 1],
	"sha3-256" => &[2, 16, 840, 1, 101, 3, 4, 2, 8],
	"sha3-256WithEcDSA" => &[2, 16, 840, 1, 101, 3, 4, 3, 10],
	"sha256WithEcDSA" => &[1, 2, 840, 10045, 4, 3, 2],
	"ecdsa" => &[1, 2, 840, 10045, 2, 1],
	"ed25519" => &[1, 3, 101, 112],
	"secp256k1" => &[1, 3, 132, 0, 10],
	"account" => &[2, 23, 42, 2, 7, 11],
	"serialNumber" => &[2, 5, 4, 5],
	"member" => &[2, 5, 4, 31],
	"commonName" => &[2, 5, 4, 3],
	"hash" => &[1, 3, 6, 1, 4, 1, 8301, 3, 2, 2, 1, 1],
	"hashData" => &[2, 16, 840, 1, 101, 3, 3, 1, 3],
};

/// HashMap for an OID string to name
static OID_TO_NAME_MAP: phf::Map<&'static str, &'static str> = phf_map! {
	"2.16.840.1.101.3.4.2.1" => "sha256",
	"2.16.840.1.101.3.4.2.8" => "sha3-256",
	"2.16.840.1.101.3.4.3.10" => "sha3-256WithEcDSA",
	"1.2.840.10045.4.3.2" => "sha256WithEcDSA",
	"1.2.840.10045.2.1" => "ecdsa",
	"1.3.101.112" => "ed25519",
	"1.3.132.0.10" => "secp256k1",
	"2.23.42.2.7.11" => "account",
	"2.5.4.5" => "serialNumber",
	"2.5.4.31" => "member",
	"2.5.4.3" => "commonName",
	"1.3.6.1.4.1.8301.3.2.2.1.1" => "hash",
	"2.16.840.1.101.3.3.1.3" => "hashData",
};

/// Container for object types. Automatically decodes to specified type
/// as an ASN1Object based on tag.
/// Note: Contexts must be last.
#[derive(AsnType, Encode, Decode, Clone, Eq, PartialEq, Debug)]
#[rasn(choice)]
pub enum ASN1Object {
	#[rasn(tag(universal, 6))]
	Oid(ASN1OID),
	#[rasn(tag(universal, 17))]
	Set(ASN1Set),
	#[rasn(tag(universal, 28))]
	String(ASN1String),
	#[rasn(tag(universal, 24))]
	Date(ASN1Date),
	#[rasn(tag(universal, 3))]
	BitString(ASN1RawBitString),
	#[rasn(tag(context, 0))]
	Context(ASN1Context),
}

/// ASN1 raw bit string.
#[derive(AsnType, Clone, Eq, PartialEq, Debug)]
#[rasn(tag(universal, 3))]
pub struct ASN1RawBitString(BitString);

/// ASN1 Context.
#[derive(AsnType, Clone, Eq, PartialEq, Debug)]
#[rasn(tag(context, 0))]
pub struct ASN1Context {
	pub value: u32,
	pub contains: Box<ASN1Data>,
	pub kind: String,
}

/// ASN1 OID.
#[napi(object, js_name = "ASN1OID")]
#[derive(AsnType, Hash, Clone, Eq, PartialEq, Debug)]
#[rasn(tag(universal, 6))]
pub struct ASN1OID {
	#[napi(ts_type = "'oid'")]
	pub r#type: &'static str,
	pub oid: String,
}

/// ASN1 Set.
#[napi(object, js_name = "ASN1Set")]
#[derive(AsnType, Hash, Clone, Eq, PartialEq, Debug)]
#[rasn(tag(universal, 17))]
pub struct ASN1Set {
	#[napi(ts_type = "'set'")]
	pub r#type: &'static str,
	pub name: ASN1OID,
	pub value: String,
}

/// ASN1 String.
#[napi(object, js_name = "ASN1String")]
#[derive(AsnType, Hash, Clone, Eq, PartialEq, Debug)]
#[rasn(tag(universal, 28))]
pub struct ASN1String {
	#[napi(ts_type = "'string'")]
	pub r#type: &'static str,
	pub value: String,
	#[napi(ts_type = "'ia5' | 'utf8' | 'printable'")]
	pub kind: String,
}

/// ASN1 Date.
#[napi(object, js_name = "ASN1Date")]
#[derive(AsnType, Hash, Clone, Eq, PartialEq, Debug)]
#[rasn(tag(universal, 24))]
pub struct ASN1Date {
	#[napi(ts_type = "'date'")]
	pub r#type: &'static str,
	#[napi(ts_type = "'utc' | 'general' | 'default'")]
	pub kind: Option<String>,
	pub date: DateTime<FixedOffset>,
}

/// ASN1 JS Context Tag.
#[napi(object, js_name = "ASN1ContextTag")]
pub struct ASN1ContextTag {
	#[napi(ts_type = "'context'")]
	pub r#type: &'static str,
	#[napi(ts_type = "'implicit' | 'explicit'")]
	pub kind: String,
	pub value: u32,
	#[napi(ts_type = "any")]
	pub contains: JsUnknown,
}

/// ASN1 JS bit string.
#[napi(object, js_name = "ASN1BitString")]
pub struct ASN1BitString {
	#[napi(ts_type = "'bitstring'")]
	pub r#type: &'static str,
	pub value: JsBuffer,
}

/// Get an oid as u32 words from a canonically named identifier.
fn get_oid_from_name<T: AsRef<str>>(name: T) -> Result<&'static [u32]> {
	if let Some(oid) = NAME_TO_OID_MAP.get(name.as_ref()) {
		Ok(*oid)
	} else {
		bail!(ASN1NAPIError::UnknownOid)
	}
}

/// Get an identifer string from an Oid.
fn get_oid_string_from_oid(oid: &Oid) -> String {
	oid.iter()
		.map(|&e| e.to_string())
		.collect::<Vec<String>>()
		.join(".")
}

/// Get a canonical name from an Oid.
fn get_name_from_oid(oid: &Oid) -> Result<&str> {
	get_name_from_oid_string(get_oid_string_from_oid(oid))
}

/// Get a canonical name from an Oid.
fn get_name_from_oid_string<T: AsRef<str>>(oid: T) -> Result<&'static str> {
	if let Some(name) = OID_TO_NAME_MAP.get(oid.as_ref()) {
		Ok(*name)
	} else {
		bail!(ASN1NAPIError::UnknownOid)
	}
}

/// Objects that have a static "type" string which indentify the underlying
/// data type in JavaScript.
pub trait TypedObject<'a> {
	const TYPE: &'a str;

	fn get_type() -> &'a str {
		Self::TYPE
	}
}

impl ASN1RawBitString {
	pub fn new(mut value: BitString) -> Self {
		value.force_align();
		value.set_uninitialized(false);

		Self(value)
	}

	pub fn into_vec(self) -> Vec<u8> {
		self.0.into_vec()
	}
}

impl ASN1OID {
	/// Create a new instance of ASNOID from a string.
	pub fn new<T: AsRef<str>>(oid: T) -> Self {
		Self {
			r#type: Self::TYPE,
			oid: oid.as_ref().into(),
		}
	}
}

impl ASN1Set {
	/// Create a new instance of an ASN1Set from an ASN1OID and value.
	pub fn new<T: ToString>(name: ASN1OID, value: T) -> Self {
		Self {
			r#type: Self::TYPE,
			value: value.to_string(),
			name,
		}
	}
}

impl ASN1Context {
	/// Create a new instance of an ASN1Context from a number and ASN1Data.
	pub fn new<T: ToString>(value: u32, data: ASN1Data, kind: T) -> Self {
		Self {
			value,
			contains: Box::new(data),
			kind: kind.to_string(),
		}
	}
}

impl ASN1ContextTag {
	/// Create a new instance of an ASN1ContextTag from a number and JsUnknown.
	pub fn new(value: u32, contains: JsUnknown, kind: String) -> Self {
		Self {
			r#type: Self::TYPE,
			kind,
			value,
			contains,
		}
	}
}

impl ASN1BitString {
	/// Create a new instance of a ASN1JsBitString from a string.
	pub fn new(env: Env, value: Vec<u8>) -> Self {
		Self {
			r#type: Self::TYPE,
			value: env.create_buffer_with_data(value).unwrap().into_raw(),
		}
	}
}

// Implement TypedObject for types
type_object!(ASN1BitString, "bitstring");
type_object!(ASN1OID, "oid");
type_object!(ASN1Set, "set");
type_object!(ASN1String, "string");
type_object!(ASN1Date, "date");
type_object!(ASN1ContextTag, "context");

/// TODO Mising bits that the rasn library truncates.
impl Encode for ASN1RawBitString {
	fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: Tag) -> Result<(), E::Error> {
		let mut data = VecDeque::from(self.0.clone().into_vec());
		data.push_front(0x00);

		encoder.encode_octet_string(tag, &Vec::from(data))?;
		Ok(())
	}
}

/// TODO Mising bits that the rasn library truncates.
impl Decode for ASN1RawBitString {
	fn decode_with_tag<D: Decoder>(decoder: &mut D, tag: Tag) -> Result<Self, D::Error> {
		let mut data = VecDeque::from(decoder.decode_octet_string(tag)?);

		if let Some(val) = data.get(0) {
			if val == &0x00 {
				data.pop_front();
			}
		}

		Ok(ASN1RawBitString::new(BitString::from_vec(Vec::from(data))))
	}
}

impl Encode for ASN1OID {
	fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: Tag) -> Result<(), E::Error> {
		if self.oid.contains(['.']) {
			if let Ok(result) = get_oid_elements_from_string(&self.oid) {
				encoder.encode_object_identifier(tag, &result)?;
				Ok(())
			} else {
				Err(<E as Encoder>::Error::custom(ASN1NAPIError::UnknownOid))
			}
		} else if let Ok(result) = get_oid_from_name(&self.oid) {
			encoder.encode_object_identifier(tag, result)?;
			Ok(())
		} else {
			Err(<E as Encoder>::Error::custom(ASN1NAPIError::UnknownOid))
		}
	}
}

impl Decode for ASN1OID {
	fn decode_with_tag<D: Decoder>(decoder: &mut D, tag: Tag) -> Result<Self, D::Error> {
		if let Ok(result) = ASN1OID::try_from(decoder.decode_object_identifier(tag)?.to_vec()) {
			Ok(result)
		} else {
			Err(<D as rasn::Decoder>::Error::custom(
				ASN1NAPIError::UnknownOid,
			))
		}
	}
}

impl Encode for ASN1Set {
	fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: Tag) -> Result<(), E::Error> {
		encoder.encode_set(tag, |encoder| {
			encoder.encode_sequence(Tag::SEQUENCE, |encoder| {
				self.name.encode(encoder)?;
				self.value.encode_with_tag(encoder, Tag::PRINTABLE_STRING)?;
				Ok(())
			})?;

			Ok(())
		})?;

		Ok(())
	}
}

impl Decode for ASN1Set {
	fn decode_with_tag<D: Decoder>(decoder: &mut D, _: Tag) -> Result<Self, D::Error> {
		decoder.decode_sequence(Tag::SET, |decoder| {
			decoder.decode_sequence(Tag::SEQUENCE, |decoder| {
				let name = ObjectIdentifier::decode(decoder)?;
				let value = Any::decode(decoder)?;

				if let Ok(oid) = ASN1OID::try_from(name.to_vec()) {
					let asn1 = ASN1Decoder::new(value.as_bytes().to_owned());

					if let Ok(value) = asn1.into_string() {
						Ok(Self::new(oid, value))
					} else {
						Err(<D as Decoder>::Error::custom(
							ASN1NAPIError::UnknownStringFormat,
						))
					}
				} else {
					Err(<D as Decoder>::Error::custom(ASN1NAPIError::UnknownOid))
				}
			})
		})
	}
}

impl Encode for ASN1String {
	fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, _: Tag) -> Result<(), E::Error> {
		match self.kind.as_str() {
			"ia5" => {
				encoder.encode_utf8_string(Tag::IA5_STRING, &self.value)?;
			}
			"utf8" => {
				encoder.encode_utf8_string(Tag::UTF8_STRING, &self.value)?;
			}
			"printable" => {
				encoder.encode_utf8_string(Tag::PRINTABLE_STRING, &self.value)?;
			}
			_ => {
				return Err(<E as Encoder>::Error::custom(
					ASN1NAPIError::UnknownStringFormat,
				))
			}
		}
		Ok(())
	}
}

// @TODO String
impl Decode for ASN1String {
	fn decode_with_tag<D: Decoder>(_: &mut D, _: Tag) -> Result<Self, D::Error> {
		Err(<D as Decoder>::Error::custom(
			ASN1NAPIError::UnknownStringFormat,
		))
	}
}

impl Encode for ASN1Date {
	fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, _: Tag) -> Result<(), E::Error> {
		if let Some(kind) = self.kind.as_deref() {
			match kind {
				"utc" => {
					encoder.encode_utf8_string(
						Tag::UTC_TIME,
						&self
							.date
							.with_timezone(&Utc)
							.format(ASN1_DATE_TIME_UTC_FORMAT)
							.to_string(),
					)?;
				}
				"general" => {
					encoder.encode_utf8_string(
						Tag::GENERALIZED_TIME,
						&self
							.date
							.with_timezone(&Utc)
							.format(ASN1_DATE_TIME_GENERAL_FORMAT)
							.to_string(),
					)?;
				}
				_ => {
					if self.date.year() < 2050 {
						encoder.encode_utf8_string(
							Tag::UTC_TIME,
							&self
								.date
								.with_timezone(&Utc)
								.format(ASN1_DATE_TIME_UTC_FORMAT)
								.to_string(),
						)?;
					} else {
						encoder.encode_utf8_string(
							Tag::GENERALIZED_TIME,
							&self
								.date
								.with_timezone(&Utc)
								.format(ASN1_DATE_TIME_GENERAL_FORMAT)
								.to_string(),
						)?;
					}
				}
			}
			Ok(())
		} else {
			Err(<E as Encoder>::Error::custom(
				ASN1NAPIError::UnknownDateFormat,
			))
		}
	}
}

// @TODO Date
impl Decode for ASN1Date {
	fn decode_with_tag<D: Decoder>(_: &mut D, _: Tag) -> Result<Self, D::Error> {
		Err(<D as Decoder>::Error::custom(
			ASN1NAPIError::UnknownDateFormat,
		))
	}
}

impl Encode for ASN1Context {
	fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, _: Tag) -> Result<(), E::Error> {
		encoder.encode_explicit_prefix(Tag::new(Class::Context, self.value), &*self.contains)?;
		Ok(())
	}
}

impl Decode for ASN1Context {
	fn decode_with_tag<D: Decoder>(decoder: &mut D, _: Tag) -> Result<Self, D::Error> {
		let asn1 = ASN1Decoder::new(decoder.decode_any()?.as_bytes().to_owned());
		let mut decoder = rasn::ber::de::Decoder::new(asn1.get_raw(), DecoderOptions::ber());
		let tag = *asn1.get_tag();

		if let Ok(ASN1Data::Unknown(any)) = decoder.decode_explicit_prefix::<ASN1Data>(tag) {
			if let Ok(data) = ASN1Data::try_from(ASN1Decoder::new(any.as_bytes().to_owned())) {
				return Ok(Self::new(tag.value, data, "explicit"));
			};
		}

		Err(<D as Decoder>::Error::custom(ASN1NAPIError::UknownContext))
	}
}

impl Encode for ASN1Data {
	fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, _: Tag) -> Result<(), E::Error> {
		match self {
			ASN1Data::Array(arr) => arr.encode(encoder),
			ASN1Data::Unknown(any) => any.encode(encoder),
			ASN1Data::Object(obj) => match obj {
				ASN1Object::Oid(oid) => oid.encode(encoder),
				ASN1Object::Set(set) => set.encode(encoder),
				ASN1Object::String(string) => string.encode(encoder),
				ASN1Object::Date(date) => date.encode(encoder),
				ASN1Object::BitString(bs) => bs.encode(encoder),
				ASN1Object::Context(context) => context.encode(encoder),
			},
			ASN1Data::Utf8String(string) => string.encode_with_tag(encoder, Tag::UTF8_STRING),
			ASN1Data::UtcTime(date) => date.encode(encoder),
			ASN1Data::GeneralizedTime(date) => date
				.naive_utc()
				.format(ASN1_DATE_TIME_GENERAL_FORMAT)
				.to_string()
				.encode_with_tag(encoder, Tag::GENERALIZED_TIME),
			_ => {
				if let Ok(open) = Open::try_from(self) {
					open.encode(encoder)
				} else {
					Err(<E as Encoder>::Error::custom(
						ASN1NAPIError::UnknownJsArgument,
					))
				}
			}
		}
	}
}

impl AsRef<[u32]> for ASN1OID {
	fn as_ref(&self) -> &[u32] {
		// TODO Handle unwrap
		get_oid_from_name(&self.oid).unwrap()
	}
}

impl AsRef<[u8]> for ASN1RawBitString {
	fn as_ref(&self) -> &[u8] {
		self.0.as_raw_slice()
	}
}

impl From<Vec<u8>> for ASN1RawBitString {
	fn from(value: Vec<u8>) -> Self {
		ASN1RawBitString::new(BitString::from_vec(value))
	}
}

impl From<ASN1RawBitString> for BitString {
	fn from(value: ASN1RawBitString) -> Self {
		value.0
	}
}

impl TryFrom<JsBuffer> for ASN1RawBitString {
	type Error = Error;

	fn try_from(value: JsBuffer) -> Result<Self, Self::Error> {
		Ok(ASN1RawBitString::from(get_buffer_from_js(
			value.into_unknown(),
		)?))
	}
}

impl TryFrom<JsObject> for ASN1RawBitString {
	type Error = Error;

	fn try_from(value: JsObject) -> Result<Self, Self::Error> {
		if let Ok(buffer) = value.get_named_property::<JsBuffer>(ASN1_OBJECT_VALUE_KEY) {
			Self::try_from(buffer)
		} else {
			bail!(ASN1NAPIError::InvalidBitString)
		}
	}
}

impl TryFrom<ASN1OID> for ObjectIdentifier {
	type Error = Error;

	fn try_from(data: ASN1OID) -> Result<Self, Self::Error> {
		if let Some(oid) = Oid::new(data.as_ref()) {
			Ok(ObjectIdentifier::from(oid))
		} else {
			bail!(ASN1NAPIError::UnknownOid)
		}
	}
}

impl<'a> TryFrom<&'a [u32]> for ASN1OID {
	type Error = Error;

	/// Attempt to convert words into an ASN1OID instance.
	fn try_from(value: &'a [u32]) -> Result<Self, Self::Error> {
		if let Some(oid) = Oid::new(value) {
			let value = if let Ok(val) = get_name_from_oid(oid) {
				val.to_owned()
			} else {
				get_string_from_oid_elements(value)?
			};

			Ok(Self::new(value))
		} else {
			bail!(ASN1NAPIError::UnknownOid)
		}
	}
}

impl<'a> TryFrom<&'a [u8]> for ASN1OID {
	type Error = Error;

	/// Attempt to convert bytes into an ASN1OID instance.
	fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
		Self::try_from(value.iter().map(|&e| e as u32).collect::<Vec<u32>>())
	}
}

impl TryFrom<Vec<u32>> for ASN1OID {
	type Error = Error;

	/// Attempt to convert owned words into an ASN1OID instance.
	fn try_from(value: Vec<u32>) -> Result<Self, Self::Error> {
		Self::try_from(value.as_slice())
	}
}

impl TryFrom<JsObject> for ASN1OID {
	type Error = Error;

	/// Attempt to convert a JsObject instance into an ASN1OID instance.
	fn try_from(value: JsObject) -> Result<Self, Self::Error> {
		let oid = value.get_named_property::<JsString>(ASN1OID::TYPE)?;
		let name = oid.into_utf16()?;

		Self::try_from(name.as_str()?)
	}
}

impl<'a> TryFrom<&'a str> for ASN1OID {
	type Error = Error;

	/// Attempt to convert a string into an ASN1OID instance.
	fn try_from(value: &'a str) -> Result<Self, Self::Error> {
		if (value.contains(['.']) && Oid::new(&get_oid_elements_from_string(value)?).is_some())
			|| get_oid_from_name(value).is_ok()
		{
			Ok(Self::new(value))
		} else {
			bail!(ASN1NAPIError::UnknownOid)
		}
	}
}

impl TryFrom<String> for ASN1OID {
	type Error = Error;

	/// Attempt to convert an owned string into an ASN1OID instance.
	fn try_from(value: String) -> Result<Self, Self::Error> {
		Self::try_from(value.as_str())
	}
}

impl TryFrom<JsObject> for ASN1Set {
	type Error = Error;

	/// Attempt to convert a JsObject instance into an ASN1Set instance.
	fn try_from(value: JsObject) -> Result<Self, Self::Error> {
		let oid = ASN1OID::try_from(value.get_named_property::<JsObject>("name")?)?;
		let value = value
			.get_named_property::<JsString>(ASN1_OBJECT_VALUE_KEY)?
			.into_utf16()?;

		Ok(Self::new(oid, value.as_str()?))
	}
}

impl TryFrom<JsObject> for ASN1String {
	type Error = Error;

	/// Attempt to convert a JsObject instance into an ASN1String instance.
	fn try_from(obj: JsObject) -> Result<Self, Self::Error> {
		let kind = obj.get_named_property::<JsUnknown>(ASN1_OBJECT_KIND_KEY)?;
		let value = obj.get_named_property::<JsUnknown>(ASN1_OBJECT_VALUE_KEY)?;

		if let Ok(ValueType::String) = kind.get_type() {
			if let Ok(ValueType::String) = value.get_type() {
				let kind = get_string_from_js(kind)?;
				let value = get_string_from_js(value)?;

				if kind == "printable" && !is_printable_string(&value) {
					bail!(ASN1NAPIError::InvalidStringEncoding)
				} else if kind == "ia5" && !is_ia5_string(&value) {
					bail!(ASN1NAPIError::InvalidStringEncoding)
				}

				Ok(Self {
					r#type: Self::TYPE,
					kind: kind,
					value: value,
				})
			} else {
				bail!(ASN1NAPIError::UnknownStringFormat)
			}
		} else {
			bail!(ASN1NAPIError::UnknownStringFormat)
		}
	}
}

impl TryFrom<JsObject> for ASN1Date {
	type Error = Error;

	/// Attempt to convert a JsObject instance into an ASN1Date instance.
	fn try_from(obj: JsObject) -> Result<Self, Self::Error> {
		let kind = obj.get_named_property::<JsUnknown>(ASN1_OBJECT_KIND_KEY)?;
		let date = obj.get_named_property::<JsUnknown>(ASN1_OBJECT_DATE_KEY)?;

		let kind = match kind.get_type() {
			Ok(ValueType::String) => Some(get_string_from_js(kind)?),
			_ => Some("default".to_string()),
		};

		if date.is_date()? {
			let date = DateTime::<FixedOffset>::from_unknown(date)?;

			if kind.as_deref() == Some("utc") && date.year() >= 2050 {
				bail!(ASN1NAPIError::InvalidUtcTime)
			}

			Ok(Self {
				r#type: Self::TYPE,
				kind,
				date,
			})
		} else {
			bail!(ASN1NAPIError::UnknownDateFormat)
		}
	}
}

impl TryFrom<JsObject> for ASN1Context {
	type Error = Error;

	/// Attempt to convert a JsObject instance into an ASN1Context instance.
	fn try_from(obj: JsObject) -> Result<Self, Self::Error> {
		let value = obj.get_named_property::<JsNumber>("value")?;
		let contains = obj.get_named_property::<JsUnknown>("contains")?;

		if let Ok(contains) = ASN1Data::try_from(contains) {
			Ok(Self::new(value.get_uint32()?, contains, "explicit"))
		} else {
			bail!(ASN1NAPIError::InvalidContextNonSequence)
		}
	}
}

impl TryFrom<ASN1Decoder> for ASN1Context {
	type Error = Error;

	fn try_from(value: ASN1Decoder) -> Result<Self, Self::Error> {
		Ok(Self::new(
			value.get_tag().value / 0xa0,
			ASN1Data::try_from(value)?,
			"explicit",
		))
	}
}

impl TryFrom<JsUnknown> for ASN1Object {
	type Error = Error;

	fn try_from(value: JsUnknown) -> Result<Self, Self::Error> {
		Self::try_from(value.coerce_to_object()?)
	}
}

impl TryFrom<JsObject> for ASN1Object {
	type Error = Error;

	fn try_from(obj: JsObject) -> Result<Self, Self::Error> {
		let field = obj.get_named_property::<JsUnknown>(ASN1_OBJECT_TYPE_KEY)?;

		if let Ok(ValueType::String) = field.get_type() {
			let name = get_string_from_js(field)?;

			Ok(match name.as_str() {
				ASN1OID::TYPE => ASN1Object::Oid(ASN1OID::try_from(obj)?),
				ASN1Set::TYPE => ASN1Object::Set(ASN1Set::try_from(obj)?),
				ASN1String::TYPE => ASN1Object::String(ASN1String::try_from(obj)?),
				ASN1Date::TYPE => ASN1Object::Date(ASN1Date::try_from(obj)?),
				ASN1BitString::TYPE => ASN1Object::BitString(ASN1RawBitString::try_from(obj)?),
				ASN1ContextTag::TYPE => ASN1Object::Context(ASN1Context::try_from(obj)?),
				_ => bail!(ASN1NAPIError::UnknownFieldProperty),
			})
		} else {
			bail!(ASN1NAPIError::UnknownObject)
		}
	}
}

#[cfg(test)]
mod test {
	use super::ASN1OID;

	#[test]
	fn test_asn1oid_try_from_string() {
		let input = "sha3-256WithEcDSA";
		let result = ASN1OID::new(input);

		assert_eq!(ASN1OID::try_from(input).unwrap(), result);

		let input = "1.2.3.4";
		let result = ASN1OID::new(input);

		assert_eq!(ASN1OID::try_from(input).unwrap(), result);
	}

	#[test]
	fn test_asn1oid_try_from_words() {
		let input = vec![2, 23, 42, 2, 7, 11];
		let result = ASN1OID::new("account");

		assert_eq!(ASN1OID::try_from(input).unwrap(), result);

		let input = vec![2, 5, 4, 5];
		let result = ASN1OID::new("serialNumber");

		assert_eq!(ASN1OID::try_from(input).unwrap(), result);
	}
}

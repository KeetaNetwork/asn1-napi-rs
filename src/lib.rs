#[macro_use]
extern crate napi_derive;

#[macro_use]
extern crate phf;

mod asn1;
mod constants;
mod macros;
mod objects;
mod types;
mod utils;

use std::str::FromStr;

pub use crate::asn1::ASN1Decoder;

use anyhow::Result;
use asn1::ASN1Encoder;
use constants::{
	ASN1_NULL, ASN1_OBJECT_DATE_KEY, ASN1_OBJECT_KIND_KEY, ASN1_OBJECT_NAME_KEY,
	ASN1_OBJECT_TYPE_KEY, ASN1_OBJECT_VALUE_KEY,
};
use napi::{
	bindgen_prelude::{Array, Buffer},
	Env, JsBigInt, JsBoolean, JsBuffer, JsDate, JsNumber, JsObject, JsString, JsUnknown, ValueType,
};
use num_bigint::BigInt;
use thiserror::Error;

use objects::{
	ASN1BitString, ASN1Context, ASN1ContextTag, ASN1Date, ASN1Object, ASN1Set, ASN1String,
	TypedObject, ASN1OID,
};
use types::{ASN1Data, JsValue};
use utils::{
	convert_string_kind_to_tag, get_big_int_from_js, get_string_kind_tag, get_vec_from_js_unknown,
	get_words_from_big_int,
};

/// Library errors
#[derive(Error, Eq, PartialEq, Debug)]
enum ASN1NAPIError {
	#[error("Unable to handle this JS input type")]
	UnknownJsArgument,
	#[error("Unable to handle this object")]
	UnknownObject,
	#[error("Unable to handle this objects type field")]
	UnknownFieldProperty,
	#[error("Unable to handle this OID")]
	UnknownOid,
	#[error("The provided string is of an unknown format")]
	UnknownStringFormat,
	#[error("The provided date is of an unknown format")]
	UnknownDateFormat,
	#[error("The provided context is of an unknown format")]
	UknownContext,
	#[error("The provided ASN1 data is malformed and cannot be decoded")]
	MalformedData,
	#[error("Cannot decode bit string")]
	InvalidBitString,
	#[error("Invalid string for ASN.1 encoding")]
	InvalidStringEncoding,
	#[error("Invalid UTC time")]
	InvalidUtcTime,
	#[error("Can only handle Universal simple types for this operation")]
	InvalidSimpleTypesOnly,
	#[error("Context data must be a sequence")]
	InvalidContextNonSequence,
	#[error("Could not encode provided data into ASN.1 format")]
	InvalidDataEncoding,
}

/// Helper to convert a JS bigint to a JS Buffer
#[napi(strict, js_name = "ASN1BigIntToBuffer")]
pub fn get_buffer_from_big_int(data: JsBigInt) -> Result<Buffer> {
	Ok(get_big_int_from_js(data.into_unknown()?)?
		.to_signed_bytes_be()
		.into())
}

/// Helper to convert a JS Buffer to a JS bigint
#[napi(strict, js_name = "BufferToBigInt")]
pub fn get_big_int_from_buffer(env: Env, data: Buffer) -> Result<JsBigInt> {
	get_js_big_int_from_big_int(env, BigInt::from_signed_bytes_be(&data))
}

/// Helper to convert a JS number to a JS BigInt
#[napi(strict, js_name = "ASN1IntegerToBigInt")]
pub fn get_big_int_from_integer(
	env: Env,
	// Using 'object' because the JS library is using internal object that we don't have here.
	#[napi(ts_arg_type = "object | number")] data: i64,
) -> Result<JsBigInt> {
	get_js_big_int_from_big_int(env, BigInt::from(data))
}

/// Helper to convert a JS string to a JS BigInt
#[napi(strict, js_name = "StringToBigInt")]
pub fn get_big_int_from_string(env: Env, data: String) -> Result<JsBigInt> {
	get_js_big_int_from_big_int(env, BigInt::from_str(&data)?)
}

/// Convert JS input into ASN1 BER encoded data.
// May return undefined if "allowUndefined" is set to true and the input is undefined.
#[napi(strict, js_name = "JStoASN1", ts_return_type = "any")]
pub fn js_to_asn1(
	env: Env,
	#[napi(ts_arg_type = "Readonly<ASN1AnyJS>")] data: JsUnknown,
	#[napi(ts_arg_type = "boolean")] allow_undefined: Option<JsBoolean>,
) -> Result<JsUnknown> {
	if data.get_type()? == ValueType::Undefined {
		if allow_undefined.is_some() && allow_undefined.unwrap().get_value()? {
			return Ok(env.get_undefined()?.into_unknown());
		} else {
			return Err(ASN1NAPIError::UnknownJsArgument.into());
		}
	}

	let instance = ASN1Encoder::js_new(data);

	match instance {
		Ok(encoder) => Ok(encoder
			.into_instance(env)
			.unwrap()
			.as_object(env)
			.into_unknown()),
		Err(error) => Err(error),
	}
}

/// Convert ASN1 BER encoded data to JS native types.
/// This supports number arrays, Buffer, ArrayBufferLike, base64 or hex
/// encded strings, or null input.
#[napi(strict, js_name = "ASN1toJS", ts_return_type = "ASN1AnyJS")]
pub fn asn1_to_js(
	env: Env,
	#[napi(ts_arg_type = "ArrayBuffer")] data: JsUnknown,
) -> Result<JsUnknown> {
	let asn1 = match data.get_type()? {
		ValueType::String => {
			ASN1Decoder::try_from(data.coerce_to_string()?.into_utf8()?.as_str()?)?
		}
		ValueType::Null => ASN1Decoder::new(ASN1_NULL.to_owned()),
		_ => ASN1Decoder::new(get_vec_from_js_unknown(data)?),
	};

	get_js_unknown_from_asn1_data(env, ASN1Data::try_from(asn1)?)
}

/// Get a JsObject from an iterator of ASN1Data.
pub(crate) fn get_js_obj_from_asn_data<T: Iterator<Item = ASN1Data>>(
	env: Env,
	data: T,
) -> Result<JsObject> {
	Ok(get_js_array_from_asn_data(env, data)?.coerce_to_object()?)
}

/// Get an Array from an iterator of ASN1Data.
pub(crate) fn get_js_array_from_asn_iter<T: Iterator<Item = Result<ASN1Data>>>(
	env: Env,
	data: T,
) -> Result<Array> {
	get_js_array_from_asn_data(
		env,
		#[allow(clippy::needless_question_mark)] // Safety check
		data.map(|result| Ok(result?))
			.map(|result: Result<ASN1Data>| cast_data!(result, Result::Ok)),
	)
}

/// Get an Array from an iterator of ASN1Data.
/// TODO Find out why this started all of a sudden
#[allow(clippy::manual_try_fold)]
pub(crate) fn get_js_array_from_asn_data<T: Iterator<Item = ASN1Data>>(
	env: Env,
	data: T,
) -> Result<Array> {
	data.map(|data| get_js_unknown_from_asn1_data(env, data))
		.enumerate()
		.fold(Ok(env.create_array(0)?), |arr, (i, unknown)| {
			let mut arr = arr.unwrap();

			arr.set(i as u32, unknown?)?;
			Ok(arr)
		})
}

/// Get a JsBigInt from a BigInt.
pub(crate) fn get_js_big_int_from_big_int(env: Env, data: BigInt) -> Result<JsBigInt> {
	let (negative, words) = get_words_from_big_int(data);
	Ok(env.create_bigint_from_words(negative, words)?)
}

/// Get an ASN1ContextTag from an ASN1Context.
pub(crate) fn get_js_context_tag_from_asn1_context(
	env: Env,
	data: ASN1Context,
) -> Result<ASN1ContextTag> {
	Ok(ASN1ContextTag::new(
		data.value,
		get_js_unknown_from_asn1_data(env, *data.contains)?,
		data.kind,
	))
}

/// Get a JsUnknown from ASN1Data.
fn get_js_unknown_from_asn1_data(env: Env, data: ASN1Data) -> Result<JsUnknown> {
	JsUnknown::try_from(JsValue::try_from((env, data))?)
}

fn get_js_obj_from_asn_string(env: Env, value: String, kind: String) -> Result<JsObject> {
	let mut obj = env.create_object()?;

	obj.set_named_property::<JsString>(ASN1_OBJECT_TYPE_KEY, env.create_string(ASN1String::TYPE)?)?;
	obj.set_named_property::<JsString>(ASN1_OBJECT_KIND_KEY, env.create_string(&kind)?)?;
	obj.set_named_property::<JsString>(ASN1_OBJECT_VALUE_KEY, env.create_string(&value)?)?;

	Ok(obj)
}

/// Get a JsObject from an ANS1Object.
/// Note: Wrapping native objects results in empty JS objects and therefore
/// must be manually built.
fn get_js_obj_from_asn_object(env: Env, data: ASN1Object) -> Result<JsObject> {
	let mut obj = env.create_object()?;

	match data {
		ASN1Object::Oid(val) => {
			obj.set_named_property::<JsString>(
				ASN1_OBJECT_TYPE_KEY,
				env.create_string(ASN1OID::TYPE)?,
			)?;
			obj.set_named_property::<JsString>(ASN1OID::TYPE, env.create_string(&val.oid)?)?;
		}
		ASN1Object::Set(val) => {
			let mut oid = env.create_object()?;

			oid.set_named_property::<JsString>(
				ASN1_OBJECT_TYPE_KEY,
				env.create_string(ASN1OID::TYPE)?,
			)?;
			oid.set_named_property::<JsString>(ASN1OID::TYPE, env.create_string(&val.name.oid)?)?;

			obj.set_named_property::<JsString>(
				ASN1_OBJECT_TYPE_KEY,
				env.create_string(ASN1Set::TYPE)?,
			)?;
			obj.set_named_property::<JsObject>(ASN1_OBJECT_NAME_KEY, oid)?;

			/* Convert the value to an appropriate String representation */
			let value_kind = convert_string_kind_to_tag(&val.value.kind)?;
			let value_nominal_kind = get_string_kind_tag(&val.value.value);

			/* If they are different, we need to return the value as an ASN1String */
			if value_kind != value_nominal_kind {
				let mut asn1_string = env.create_object()?;
				asn1_string.set_named_property::<JsString>(
					ASN1_OBJECT_TYPE_KEY,
					env.create_string(ASN1String::TYPE)?,
				)?;
				asn1_string.set_named_property::<JsString>(
					ASN1_OBJECT_KIND_KEY,
					env.create_string(&val.value.kind)?,
				)?;
				asn1_string.set_named_property::<JsString>(
					ASN1_OBJECT_VALUE_KEY,
					env.create_string(&val.value.value)?,
				)?;
				obj.set_named_property::<JsObject>(ASN1_OBJECT_VALUE_KEY, asn1_string)?;
			} else {
				/* Otherwise we need to return the value as a primitive string */
				obj.set_named_property::<JsString>(
					ASN1_OBJECT_VALUE_KEY,
					env.create_string(&val.value.value)?,
				)?;
			}
		}
		ASN1Object::String(val) => {
			obj.set_named_property::<JsString>(
				ASN1_OBJECT_TYPE_KEY,
				env.create_string(ASN1String::TYPE)?,
			)?;
			obj.set_named_property::<JsString>(
				ASN1_OBJECT_KIND_KEY,
				env.create_string(&val.kind)?,
			)?;
			obj.set_named_property::<JsString>(
				ASN1_OBJECT_VALUE_KEY,
				env.create_string(&val.value)?,
			)?;
		}
		ASN1Object::Date(val) => {
			obj.set_named_property::<JsString>(
				ASN1_OBJECT_TYPE_KEY,
				env.create_string(ASN1Date::TYPE)?,
			)?;

			if let Some(kind_str) = val.kind.as_deref() {
				obj.set_named_property::<JsString>(
					ASN1_OBJECT_KIND_KEY,
					env.create_string(kind_str)?,
				)?;
			}

			let timestamp_ms = val.date.timestamp_millis() as f64;
			obj.set_named_property::<JsDate>(ASN1_OBJECT_DATE_KEY, env.create_date(timestamp_ms)?)?;
		}
		ASN1Object::BitString(val) => {
			obj.set_named_property::<JsString>(
				ASN1_OBJECT_TYPE_KEY,
				env.create_string(ASN1BitString::TYPE)?,
			)?;
			obj.set_named_property::<JsBuffer>(
				ASN1_OBJECT_VALUE_KEY,
				ASN1BitString::new(env, val.value.into_vec(), None).value,
			)?;
			if let Some(unused_bits) = val.unused_bits {
				obj.set_named_property::<JsNumber>(
					"unusedBits",
					env.create_uint32(unused_bits.into())?,
				)?;
			}
		}
		ASN1Object::Context(val) => {
			obj.set_named_property::<JsString>(
				ASN1_OBJECT_TYPE_KEY,
				env.create_string(ASN1ContextTag::TYPE)?,
			)?;
			obj.set_named_property::<JsString>(
				ASN1_OBJECT_KIND_KEY,
				env.create_string(&val.kind)?,
			)?;
			obj.set_named_property::<JsNumber>(
				ASN1_OBJECT_VALUE_KEY,
				env.create_uint32(val.value)?,
			)?;
			obj.set_named_property::<JsUnknown>(
				"contains",
				get_js_unknown_from_asn1_data(env, *val.contains)?,
			)?;
		}
	};

	Ok(obj)
}

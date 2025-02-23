use std::str::FromStr;

use anyhow::{bail, Result};
use chrono::{DateTime, Datelike, FixedOffset, NaiveDateTime, Utc};
use napi::{
	bindgen_prelude::FromNapiValue, Env, JsArrayBuffer, JsBoolean, JsBuffer, JsDate, JsNumber,
	JsString, JsUnknown, ValueType,
};
use num_bigint::{BigInt, Sign};
use rasn::{ber::de::DecoderOptions, types::Utf8String, Decode, Tag};

use crate::{
	constants::{ASN1_DATE_TIME_GENERAL_FORMAT, ASN1_DATE_TIME_UTC_FORMAT},
	get_js_obj_from_asn_string,
	types::{ASN1Data, JsValue},
	ASN1NAPIError,
};

/// Get utf16 bytes from a string.
pub(crate) fn get_utf16_from_string<T: AsRef<str>>(value: T) -> Vec<u16> {
	value.as_ref().encode_utf16().collect::<Vec<u16>>()
}

/// Get a Vec<u32> of the numbers in an OID string.
pub(crate) fn get_oid_elements_from_string<T: AsRef<str>>(value: T) -> Result<Vec<u32>> {
	value
		.as_ref()
		.split('.')
		.map(str::parse::<u32>)
		.map(|r| Ok(r?))
		.collect()
}

/// Get a string representation of the OID.
pub(crate) fn get_string_from_oid_elements<T: AsRef<[u32]>>(value: T) -> Result<String> {
	Ok(value
		.as_ref()
		.iter()
		.map(|v| v.to_string())
		.collect::<Vec<String>>()
		.join("."))
}

/// Get a sign as a bool and a Vec<u64> of words from a BigInt.
pub(crate) fn get_words_from_big_int(data: BigInt) -> (bool, Vec<u64>) {
	let (sign, words) = data.to_u64_digits();
	(sign == Sign::Minus, words)
}

/// Helper for handling date/times with milliseconds
/// TODO rasn library does not properly handle dates with milliseconds.
#[allow(deprecated)]
pub(crate) fn get_utc_date_time_from_asn1_milli<T: AsRef<[u8]>>(data: T) -> Result<DateTime<Utc>> {
	let mut decoder = rasn::ber::de::Decoder::new(data.as_ref(), DecoderOptions::ber());
	let (decoded, format) = match data.as_ref().first().unwrap_or(&0) {
		0x17 => (
			Utf8String::decode_with_tag(&mut decoder, Tag::UTC_TIME),
			ASN1_DATE_TIME_UTC_FORMAT,
		),
		0x18 => (
			Utf8String::decode_with_tag(&mut decoder, Tag::GENERALIZED_TIME),
			ASN1_DATE_TIME_GENERAL_FORMAT,
		),
		_ => bail!(ASN1NAPIError::MalformedData),
	};

	if let Ok(decoded) = decoded {
		if let Some(offset) = FixedOffset::east_opt(0) {
			Ok(DateTime::<FixedOffset>::from_utc(
				NaiveDateTime::parse_from_str(&decoded, format)?,
				offset,
			)
			.with_timezone(&Utc))
		} else {
			bail!(ASN1NAPIError::MalformedData)
		}
	} else {
		bail!(ASN1NAPIError::MalformedData)
	}
}

/// Get an chrono datetime from a JsUnknown.
/// JavaScript Date objects are described in
/// [Section 20.3](https://tc39.github.io/ecma262/#sec-date-objects)
/// of the ECMAScript Language Specification.
#[allow(deprecated)]
pub(crate) fn get_fixed_date_from_js(data: JsUnknown) -> Result<DateTime<FixedOffset>> {
	let js_date = JsDate::try_from(data)?;
	let timestamp = js_date.value_of()? as i64;
	let ts_secs = timestamp / 1000;
	let ts_ns = ((timestamp % 1000) * 1_000_000) as u32;

	if let (Some(datetime), Some(offset)) = (
		NaiveDateTime::from_timestamp_opt(ts_secs, ts_ns),
		FixedOffset::east_opt(0),
	) {
		Ok(DateTime::<FixedOffset>::from_utc(datetime, offset))
	} else {
		bail!(ASN1NAPIError::MalformedData)
	}
}

/// Get an ASN1 boolean from a JsUnknown.
pub(crate) fn get_boolean_from_js(data: JsUnknown) -> Result<bool> {
	Ok(JsBoolean::from_unknown(data)?.get_value()?)
}

/// Get a string from a JsUnknown.
pub(crate) fn get_string_from_js(data: JsUnknown) -> Result<String> {
	Ok(JsString::from_unknown(data)?.into_utf8()?.into_owned()?)
}

/// Get an i64 integer from a JsUnknown.
pub(crate) fn get_integer_from_js(data: JsUnknown) -> Result<i64> {
	Ok(JsNumber::from_unknown(data)?.get_int64()?)
}

/// Get an i128 integer from a JsUnknown.
pub(crate) fn get_big_int_from_js(data: JsUnknown) -> Result<BigInt> {
	Ok(BigInt::from_str(
		data.coerce_to_string()?.into_utf8()?.as_str()?,
	)?)
}

/// Get a Vec<u8> via a JsBuffer from a JsUnknown.
pub(crate) fn get_buffer_from_js(data: JsUnknown) -> Result<Vec<u8>> {
	Ok(JsBuffer::from_unknown(data)?.into_value()?.to_vec())
}

/// Get a Vec<u8> via a JsArrayBuffer from a JsUnknown.
pub(crate) fn get_array_buffer_from_js(data: JsUnknown) -> Result<Vec<u8>> {
	Ok(JsArrayBuffer::from_unknown(data)?.into_value()?.to_vec())
}

/// Get a Vec<u8> from a JsUnknown.
pub(crate) fn get_vec_from_js(data: JsUnknown) -> Result<Vec<u8>> {
	Ok(Vec::<u8>::from_unknown(data)?)
}

/// Get a Vec<ASN1Data> from a JsUnknown.
pub(crate) fn get_array_from_js(data: JsUnknown) -> Result<Vec<ASN1Data>> {
	let obj = data.coerce_to_object()?;
	let len = obj.get_array_length()?;
	let mut result = Vec::new();

	for i in 0..len {
		result.push(ASN1Data::try_from(obj.get_element::<JsUnknown>(i)?)?);
	}

	Ok(result)
}

/// Get a Vec<u8> from a JsUnknown.
pub(crate) fn get_vec_from_js_unknown(data: JsUnknown) -> Result<Vec<u8>> {
	Ok(match data.get_type()? {
		ValueType::Object if data.is_array()? => get_vec_from_js(data)?,
		ValueType::Object if data.is_buffer()? => get_buffer_from_js(data)?,
		// There is no check for is_array_buffer in NAPI
		// TODO create a pull request for them
		_ => get_array_buffer_from_js(data)?,
	})
}

/// Get an ASN1Data String from a JsUnknown.
pub(crate) fn get_asn_string_type_from_js_unknown(data: JsUnknown) -> Result<ASN1Data> {
	let data = get_string_from_js(data)?;
	if is_printable_string(&data) {
		Ok(ASN1Data::PrintableString(data.into()))
	} else if is_ia5_string(&data) {
		Ok(ASN1Data::Ia5String(data.into()))
	} else {
		Ok(ASN1Data::Utf8String(data.into()))
	}
}

/// Get an ASN1Data Date from a JsUnknown.
pub(crate) fn get_asn_date_type_from_js_unknown(data: JsUnknown) -> Result<ASN1Data> {
	let date = get_fixed_date_from_js(data)?;
	if date.year() < 2050 {
		Ok(ASN1Data::UtcTime(date.to_utc()))
	} else {
		Ok(ASN1Data::GeneralizedTime(date))
	}
}

/// Get an JsValue String from an ASN1Data.
pub(crate) fn get_js_value_from_asn1_data(env: Env, kind: &str, value: &str) -> Result<JsValue> {
	Ok(match kind {
		"PrintableString" => {
			JsValue::String(env.create_string_utf16(get_utf16_from_string(value).as_ref())?)
		}
		"Ia5String" => {
			if is_printable_string(value) {
				JsValue::Object(get_js_obj_from_asn_string(
					env,
					value.to_string(),
					"ia5".to_string(),
				)?)
			} else {
				JsValue::String(env.create_string_utf16(get_utf16_from_string(value).as_ref())?)
			}
		}
		"Utf8String" => {
			if is_printable_string(value) || is_ia5_string(value) {
				JsValue::Object(get_js_obj_from_asn_string(
					env,
					value.to_string(),
					"utf8".to_string(),
				)?)
			} else {
				JsValue::String(env.create_string_utf16(get_utf16_from_string(value).as_ref())?)
			}
		}
		_ => bail!(ASN1NAPIError::UnknownStringFormat),
	})
}

/// Check if a string is a printable string.
pub(crate) fn is_printable_string(data: &str) -> bool {
	let data: String = data
		.chars()
		.skip_while(|&c| !c.is_ascii_graphic())
		.collect();
	data.chars().all(|c| {
		matches!(c,
			'a'..='z' | 'A'..='Z' | '0'..='9' | ' ' |
			'\'' | '(' | ')' | '+' | ',' | '.' | '/' |
			':' | '=' | '?' | '-'
		)
	})
}

/// Check if a string is an IA5 string.
pub(crate) fn is_ia5_string(data: &str) -> bool {
	data.chars().all(|c| c.is_ascii())
}

/// The "rasn" library authors forgot to include a way to get the header
/// length for a tag, so we must re-implement ASN.1 BER parsing here.
pub(crate) fn header_length(data: &[u8]) -> Result<usize, &'static str> {
	let mut pos = 0;
	if data.is_empty() {
		return Err("data too short for tag");
	}

	// Parse the tag field.
	// The first byte contains the tag class, primitive/constructed bit, and tag number.
	let first_tag_byte = data[0];
	pos += 1;

	// If the tag number is 31 (0x1F), then the tag is encoded in multiple bytes.
	if first_tag_byte & 0x1F == 0x1F {
		// Continue reading bytes until a byte with the high bit clear is found.
		while pos < data.len() {
			let tag_byte = data[pos];
			pos += 1;
			if tag_byte & 0x80 == 0 {
				break;
			}
		}
	}

	// Ensure there's at least one byte for the length field.
	if pos >= data.len() {
		return Err("data too short for length field");
	}

	// Parse the length field.
	let length_byte = data[pos];
	pos += 1;
	if length_byte & 0x80 != 0 {
		// Long form: the low 7 bits tell us how many subsequent bytes represent the length.
		let num_len_bytes = (length_byte & 0x7F) as usize;
		if pos + num_len_bytes > data.len() {
			return Err("data too short for long form length bytes");
		}
		pos += num_len_bytes;
	}

	Ok(pos)
}

#[cfg(test)]
mod test {
	use chrono::{TimeZone, Utc};
	use num_bigint::BigInt;

	use crate::utils::get_utf16_from_string;

	use super::get_oid_elements_from_string;
	use super::get_string_from_oid_elements;
	use super::get_utc_date_time_from_asn1_milli;
	use super::get_words_from_big_int;

	#[test]
	fn test_get_utf16_from_string() {
		assert_eq!(get_utf16_from_string("test"), vec![0x74, 0x65, 0x73, 0x74]);
	}

	#[test]
	fn test_get_oid_elements_from_string() {
		assert_eq!(
			get_oid_elements_from_string("2.5.4.5").unwrap(),
			vec![2, 5, 4, 5]
		);
	}

	#[test]
	fn test_get_string_from_oid_elements() {
		assert_eq!(
			get_string_from_oid_elements([2, 5, 4, 5]).unwrap(),
			"2.5.4.5"
		);
	}

	#[test]
	fn test_get_words_from_big_int() {
		let input = BigInt::from(18591708106338011145_i128);
		let (negative, words) = get_words_from_big_int(input);

		assert!(!negative);
		assert_eq!(words, vec![0x203040506070809, 0x01]);

		let input = BigInt::from(-18591708106338011145_i128);
		let (negative, words) = get_words_from_big_int(input);

		assert!(negative);
		assert_eq!(words, vec![0x203040506070809, 0x01]);
	}

	#[test]
	fn test_get_utc_date_time_from_asn1_milli() {
		let date = Utc.timestamp_millis_opt(1655921880210).unwrap();
		let input = [
			24, 19, 50, 48, 50, 50, 48, 54, 50, 50, 49, 56, 49, 56, 48, 48, 46, 50, 49, 48, 90,
		];

		assert_eq!(get_utc_date_time_from_asn1_milli(input).unwrap(), date);

		let date = Utc.with_ymd_and_hms(2022, 9, 26, 10, 0, 0).unwrap();
		let input = [
			24, 15, 50, 48, 50, 50, 48, 57, 50, 54, 49, 48, 48, 48, 48, 48, 90,
		];

		assert_eq!(get_utc_date_time_from_asn1_milli(input).unwrap(), date);
	}
}

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
	constants::{ASN1_DATE_TIME_GENERAL_FORMAT_WITH_MS, ASN1_DATE_TIME_UTC_FORMAT},
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
	let (decoded, format, is_utc_time) = match data.as_ref().first().unwrap_or(&0) {
		0x17 => (
			Utf8String::decode_with_tag(&mut decoder, Tag::UTC_TIME),
			ASN1_DATE_TIME_UTC_FORMAT,
			true,
		),
		0x18 => (
			Utf8String::decode_with_tag(&mut decoder, Tag::GENERALIZED_TIME),
			ASN1_DATE_TIME_GENERAL_FORMAT_WITH_MS,
			false,
		),
		_ => bail!(ASN1NAPIError::MalformedData),
	};

	if let Ok(decoded) = decoded {
		if let Some(offset) = FixedOffset::east_opt(0) {
			let mut naive = NaiveDateTime::parse_from_str(&decoded, format)?;

			// RFC 5280 §4.1.2.5.1: UTCTime pivots at 50 (>= 50 → 19xx),
			// but chrono's %y pivots at 70. Correct the 50-69 range.
			// See `<https://github.com/chronotope/chrono/issues/1152>`
			if is_utc_time && naive.year() >= 2050 {
				naive = naive
					.with_year(naive.year() - 100)
					.ok_or(ASN1NAPIError::MalformedData)?;
			}

			Ok(DateTime::<FixedOffset>::from_utc(naive, offset).with_timezone(&Utc))
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

/// Return the kind of string this should be encoded as
pub(crate) fn get_string_kind_tag(data: &str) -> Tag {
	if is_printable_string(data) {
		Tag::PRINTABLE_STRING
	} else if is_ia5_string(data) {
		Tag::IA5_STRING
	} else {
		Tag::UTF8_STRING
	}
}

pub(crate) fn convert_string_kind_to_tag(kind: &str) -> Result<Tag> {
	Ok(match kind {
		"printable" => Tag::PRINTABLE_STRING,
		"ia5" => Tag::IA5_STRING,
		"utf8" => Tag::UTF8_STRING,
		_ => bail!(ASN1NAPIError::UnknownStringFormat),
	})
}

pub(crate) fn get_string_kind_from_tag(tag: Tag) -> &'static str {
	match tag {
		Tag::PRINTABLE_STRING => "printable",
		Tag::IA5_STRING => "ia5",
		Tag::UTF8_STRING => "utf8",
		_ => "unknown",
	}
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

/// Read one BER header at `pos`. Returns whether the element is constructed,
/// where its content starts, and its content length (`None` for indefinite
/// length). Returns `None` when the header cannot be read.
fn read_ber_header(data: &[u8], pos: usize) -> Option<(bool, usize, Option<usize>)> {
	let first = *data.get(pos)?;
	let constructed = first & 0x20 != 0;
	let mut pos = pos + 1;

	if first & 0x1F == 0x1F {
		loop {
			let tag_byte = *data.get(pos)?;
			pos += 1;
			if tag_byte & 0x80 == 0 {
				break;
			}
		}
	}

	let length_byte = *data.get(pos)?;
	pos += 1;

	let length = match length_byte {
		0x00..=0x7F => Some(length_byte as usize),
		0x80 if constructed => None,
		0x80 => return None,
		_ => {
			let mut length: usize = 0;
			for _ in 0..(length_byte & 0x7F) {
				length = length
					.checked_mul(0x100)?
					.checked_add(*data.get(pos)? as usize)?;
				pos += 1;
			}
			Some(length)
		}
	};

	Some((constructed, pos, length))
}

/// Reject BER data whose constructed elements nest deeper than `max_depth`.
///
/// Decoding recurses once per nesting level, so this bounds the native stack
/// that one input can use. It walks the headers of the first element without
/// recursion before anything is decoded.
///
/// Only nesting is rejected here. When a header cannot be read, the walk skips
/// to the end of the innermost definite-length element that holds it, which is
/// where the decoder gives up on that element too, and leaves the error to the
/// decoder.
pub(crate) fn check_nesting_depth(data: &[u8], max_depth: usize) -> Result<()> {
	// End offset of each open constructed element, `None` for indefinite length.
	let mut open: Vec<Option<usize>> = Vec::new();
	let mut pos = 0;

	loop {
		while let Some(&Some(end)) = open.last() {
			if pos < end {
				break;
			}
			open.pop();
		}

		if open.is_empty() && pos > 0 {
			return Ok(());
		}

		if open.last() == Some(&None) && data.get(pos..pos + 2) == Some(&[0, 0]) {
			open.pop();
			pos += 2;
			continue;
		}

		let limit = open.iter().rev().find_map(|end| *end).unwrap_or(data.len());
		let header = read_ber_header(data, pos).and_then(|(constructed, start, length)| {
			let end = match length {
				Some(length) => Some(start.checked_add(length)?),
				None => None,
			};

			if pos >= limit || end.unwrap_or(start) > limit {
				return None;
			}

			Some((constructed, start, end))
		});

		match header {
			Some((true, start, end)) => {
				open.push(end);
				if open.len() > max_depth {
					bail!(ASN1NAPIError::NestingTooDeep);
				}
				pos = start;
			}
			Some((false, _, Some(end))) => pos = end,
			_ => loop {
				match open.pop() {
					None => return Ok(()),
					Some(None) => continue,
					Some(Some(end)) => {
						pos = end;
						break;
					}
				}
			},
		}
	}
}

#[cfg(test)]
mod test {
	use anyhow::Result;
	use chrono::{Datelike, TimeZone, Utc};
	use num_bigint::BigInt;

	use crate::utils::get_utf16_from_string;

	use super::check_nesting_depth;
	use super::get_oid_elements_from_string;
	use super::get_string_from_oid_elements;
	use super::get_utc_date_time_from_asn1_milli;
	use super::get_words_from_big_int;

	fn build_time_der(tag: u8, time_str: &str) -> Vec<u8> {
		let bytes = time_str.as_bytes();
		let mut der = Vec::with_capacity(2 + bytes.len());
		der.push(tag);
		der.push(bytes.len() as u8);
		der.extend_from_slice(bytes);
		der
	}

	fn utc_time_der(time_str: &str) -> Vec<u8> {
		build_time_der(0x17, time_str)
	}

	fn generalized_time_der(time_str: &str) -> Vec<u8> {
		build_time_der(0x18, time_str)
	}

	#[test]
	fn test_get_utf16_from_string() {
		assert_eq!(get_utf16_from_string("test"), vec![0x74, 0x65, 0x73, 0x74]);
	}

	#[test]
	fn test_oid_roundtrip() -> Result<()> {
		let cases: &[(&str, &[u32])] = &[("2.5.4.5", &[2, 5, 4, 5])];

		for (string, elements) in cases {
			assert_eq!(
				get_oid_elements_from_string(string)?,
				*elements,
				"parse {string}"
			);
			assert_eq!(
				get_string_from_oid_elements(*elements)?,
				*string,
				"format {elements:?}"
			);
		}

		Ok(())
	}

	#[test]
	fn test_get_words_from_big_int() {
		let cases: &[(i128, bool, &[u64])] = &[
			(18591708106338011145, false, &[0x203040506070809, 0x01]),
			(-18591708106338011145, true, &[0x203040506070809, 0x01]),
		];

		for (value, expected_negative, expected_words) in cases {
			let (negative, words) = get_words_from_big_int(BigInt::from(*value));
			assert_eq!(negative, *expected_negative, "sign for {value}");
			assert_eq!(words.as_slice(), *expected_words, "words for {value}");
		}
	}

	#[test]
	fn test_utc_time_rfc5280_pivot() -> Result<()> {
		// RFC 5280 §4.1.2.5.1: >= 50 → 19xx, < 50 → 20xx
		let cases: &[(&str, i32)] = &[
			("000601120000Z", 2000), // below pivot, 21st century
			("490601120000Z", 2049), // boundary: last year below pivot
			("500601120000Z", 1950), // boundary: first year at pivot
			("690101000000Z", 1969), // above pivot, chrono disagrees (bug case)
			("700601120000Z", 1970), // at chrono's pivot, both agree
			("990601120000Z", 1999), // max 2-digit year
		];

		for (time_str, expected_year) in cases {
			let result = get_utc_date_time_from_asn1_milli(utc_time_der(time_str))?;
			assert_eq!(
				result.year(),
				*expected_year,
				"UTCTime {time_str} should decode to year {expected_year}"
			);
		}

		Ok(())
	}

	#[test]
	fn test_generalized_time_decode() -> Result<()> {
		let cases = [
			(
				"20220622181800.210Z",
				Utc.timestamp_millis_opt(1655921880210).single(),
			),
			(
				"20220926100000Z",
				Utc.with_ymd_and_hms(2022, 9, 26, 10, 0, 0).single(),
			),
		];

		for (time_str, expected) in cases {
			let expected =
				expected.ok_or_else(|| anyhow::anyhow!("invalid test date {time_str}"))?;
			let result = get_utc_date_time_from_asn1_milli(generalized_time_der(time_str))?;
			assert_eq!(result, expected, "GeneralizedTime {time_str}");
		}

		Ok(())
	}

	/// Wrap an INTEGER in `depth` definite-length SEQUENCEs.
	fn nested_sequences(depth: usize) -> Vec<u8> {
		let mut data = vec![0x02, 0x01, 0x01];
		for _ in 0..depth {
			let length = data.len();
			let mut wrapped = vec![0x30];
			if length < 0x80 {
				wrapped.push(length as u8);
			} else {
				let bytes: Vec<u8> = length
					.to_be_bytes()
					.into_iter()
					.skip_while(|byte| *byte == 0)
					.collect();
				wrapped.push(0x80 | bytes.len() as u8);
				wrapped.extend(bytes);
			}
			wrapped.extend(data);
			data = wrapped;
		}
		data
	}

	/// Wrap an INTEGER in `depth` indefinite-length SEQUENCEs.
	fn nested_indefinite_sequences(depth: usize) -> Vec<u8> {
		let mut data = vec![0x30, 0x80].repeat(depth);
		data.extend([0x02, 0x01, 0x01]);
		data.extend([0x00, 0x00].repeat(depth));
		data
	}

	#[test]
	fn test_check_nesting_depth_at_limit() {
		assert!(check_nesting_depth(&nested_sequences(8), 8).is_ok());
		assert!(check_nesting_depth(&nested_indefinite_sequences(8), 8).is_ok());
		assert!(check_nesting_depth(&[0x02, 0x01, 0x01], 0).is_ok());
	}

	#[test]
	fn test_check_nesting_depth_over_limit() {
		assert!(check_nesting_depth(&nested_sequences(9), 8).is_err());
		assert!(check_nesting_depth(&nested_indefinite_sequences(9), 8).is_err());
		assert!(check_nesting_depth(&nested_sequences(100_000), 128).is_err());
	}

	#[test]
	fn test_check_nesting_depth_counts_depth_not_width() {
		// Many siblings at one level are not nesting
		let mut content = Vec::new();
		for _ in 0..1000 {
			content.extend(nested_sequences(4));
		}
		let mut data = vec![0x30, 0x82, (content.len() >> 8) as u8, content.len() as u8];
		data.extend(content);
		assert!(check_nesting_depth(&data, 5).is_ok());
		assert!(check_nesting_depth(&data, 4).is_err());
	}

	#[test]
	fn test_check_nesting_depth_ignores_trailing_data() {
		let mut data = vec![0x02, 0x01, 0x01];
		data.extend(nested_sequences(10));
		assert!(check_nesting_depth(&data, 2).is_ok());
	}

	#[test]
	fn test_check_nesting_depth_leaves_malformed_data_to_decoder() {
		assert!(check_nesting_depth(&[], 8).is_ok());
		assert!(check_nesting_depth(&[0x30], 8).is_ok());
		assert!(check_nesting_depth(&[0x30, 0x05, 0x02], 8).is_ok());
		assert!(check_nesting_depth(&[0x30, 0x89, 1, 2, 3, 4, 5, 6, 7, 8, 9], 8).is_ok());
	}

	#[test]
	fn test_check_nesting_depth_after_malformed_sibling() {
		// A malformed element ends the walk of its definite-length parent, but
		// a deep sibling of that parent is still checked
		let deep = nested_sequences(20);
		let broken = vec![0x30, 0x03, 0x04, 0x7F, 0x00];
		let mut content = broken;
		content.extend(&deep);
		let mut data = vec![0x30, 0x82, (content.len() >> 8) as u8, content.len() as u8];
		data.extend(content);
		assert!(check_nesting_depth(&data, 10).is_err());
	}

	#[test]
	fn test_check_nesting_depth_with_default_limit() {
		for depth in [
			nested_sequences(1),
			nested_sequences(127),
			nested_indefinite_sequences(128),
		] {
			assert!(check_nesting_depth(&depth, crate::constants::ASN1_MAX_NESTING_DEPTH).is_ok());
		}
		assert!(check_nesting_depth(
			&nested_sequences(129),
			crate::constants::ASN1_MAX_NESTING_DEPTH
		)
		.is_err());
	}
}

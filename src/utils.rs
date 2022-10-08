use std::str::FromStr;

use anyhow::{bail, Result};
use chrono::{DateTime, FixedOffset, NaiveDateTime, Utc};
use napi::{
    bindgen_prelude::FromNapiValue, JsArrayBuffer, JsBoolean, JsBuffer, JsDate, JsNumber, JsString,
    JsUnknown, ValueType,
};
use num_bigint::{BigInt, Sign};
use rasn::{ber::de::DecoderOptions, types::Utf8String, Decode, Tag};

use crate::{constants::ANS1_DATE_TIME_UTC_FORMAT, types::ASN1Data, ASN1NAPIError};

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

pub(crate) fn get_string_from_oid_elements<T: AsRef<[u32]>>(value: T) -> Result<String> {
    Ok(value
        .as_ref()
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<String>>()
        .join("."))
}

/// Get an chrono datetime from a JsUnknown.
/// JavaScript Date objects are described in
/// [Section 20.3](https://tc39.github.io/ecma262/#sec-date-objects)
/// of the ECMAScript Language Specification.
pub(crate) fn get_fixed_date_from_js(data: JsUnknown) -> Result<DateTime<FixedOffset>> {
    let js_date = JsDate::try_from(data)?;
    let timestamp = js_date.value_of()? as i64;
    let ts_secs = timestamp / 1000;
    let ts_ns = ((timestamp % 1000) * 1_000_000) as u32;
    let naive = NaiveDateTime::from_timestamp(ts_secs, ts_ns);

    Ok(DateTime::<FixedOffset>::from_utc(
        naive,
        FixedOffset::east(0),
    ))
}

/// Get a sign as a bool and a Vec<u64> of words from a BigInt.
pub(crate) fn get_words_from_big_int(data: BigInt) -> (bool, Vec<u64>) {
    let (sign, words) = data.to_u64_digits();
    (sign == Sign::Minus, words)
}

/// Helper for handling date/times with milliseconds
pub(crate) fn get_utc_date_time_from_asn1_milli<T: AsRef<[u8]>>(data: T) -> Result<DateTime<Utc>> {
    let mut decoder = rasn::ber::de::Decoder::new(data.as_ref(), DecoderOptions::ber());

    if let Ok(decoded) = Utf8String::decode_with_tag(&mut decoder, Tag::GENERALIZED_TIME) {
        Ok(DateTime::<FixedOffset>::from_utc(
            NaiveDateTime::parse_from_str(&decoded, ANS1_DATE_TIME_UTC_FORMAT)?,
            FixedOffset::east(0),
        )
        .with_timezone(&Utc))
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

#[cfg(test)]
mod test {
    use chrono::{TimeZone, Utc};
    use num_bigint::BigInt;

    use crate::utils::get_utf16_from_string;

    use super::get_oid_elements_from_string;
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
        let date = Utc.ymd(2022, 6, 22).and_hms_milli(18, 18, 0, 210);
        let input = [
            24, 19, 50, 48, 50, 50, 48, 54, 50, 50, 49, 56, 49, 56, 48, 48, 46, 50, 49, 48, 90,
        ];

        assert_eq!(get_utc_date_time_from_asn1_milli(&input).unwrap(), date);

        let date = Utc.ymd(2022, 9, 26).and_hms_milli(10, 0, 0, 0);
        let input = [
            24, 15, 50, 48, 50, 50, 48, 57, 50, 54, 49, 48, 48, 48, 48, 48, 90,
        ];

        assert_eq!(get_utc_date_time_from_asn1_milli(&input).unwrap(), date);
    }
}

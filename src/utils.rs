use std::str::FromStr;

use anyhow::{bail, Result};
use chrono::{DateTime, FixedOffset, NaiveDateTime, Utc};
use napi::{
    bindgen_prelude::{Array, FromNapiValue},
    Env, JsBigInt, JsBoolean, JsBuffer, JsDate, JsNumber, JsObject, JsString, JsUnknown,
};
use num_bigint::{BigInt, Sign};
use rasn::{types::Utf8String, Decode, Tag};

use crate::{
    asn1::ASNIterator,
    constants::ANS1_DATE_TIME_UTC_FORMAT,
    types::{ASN1Data, JsValue},
    ASN1NAPIError,
};

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

/// Get a Vec<u8> from a JsUnknown.
pub(crate) fn get_vec_from_js(data: JsUnknown) -> Result<Vec<u8>> {
    Ok(Vec::<u8>::from_unknown(data)?)
}

/// Get an Array from an ASNIterator.
pub(crate) fn get_js_array_from_asn_iter(env: Env, data: &ASNIterator) -> Result<Array> {
    get_js_array_from_asn_data(env, Vec::<ASN1Data>::try_from(data)?)
}

/// Get an Array from a Vec<ASN1Data>.
pub(crate) fn get_js_array_from_asn_data(env: Env, data: Vec<ASN1Data>) -> Result<Array> {
    let mut array = env.create_array(data.len() as u32)?;

    for (i, data) in data.iter().enumerate() {
        array.set(i as u32, get_js_uknown_from_asn_data(env, data.to_owned())?)?;
    }

    Ok(array)
}

/// Get an chrono datetime from a JsUnknown.
/// JavaScript Date objects are described in
/// [Section 20.3](https://tc39.github.io/ecma262/#sec-date-objects)
/// of the ECMAScript Language Specification.
pub(crate) fn get_fixed_date_from_js(data: JsUnknown) -> Result<DateTime<FixedOffset>> {
    let js_date = JsDate::try_from(data)?;
    let timestamp = js_date.value_of()? as i64;
    let naive = NaiveDateTime::from_timestamp(timestamp / 1000, (timestamp % 1000) as u32);

    Ok(DateTime::<FixedOffset>::from_utc(
        naive,
        FixedOffset::east(0),
    ))
}

/// Get a Vec<u64> of words from a BigInt.
pub(crate) fn get_words_from_big_int(data: BigInt) -> (bool, Vec<u64>) {
    let (sign, words) = data.to_u64_digits();
    (sign == Sign::Minus, words)
}

pub(crate) fn get_js_uknown_from_asn_data(env: Env, data: ASN1Data) -> Result<JsUnknown> {
    JsUnknown::try_from(JsValue::try_from((env, data))?)
}

/// Get a JsObject from a Vec<ASN1Data>.
pub(crate) fn get_js_obj_from_asn_data(env: Env, data: Vec<ASN1Data>) -> Result<JsObject> {
    Ok(get_js_array_from_asn_data(env, data)?.coerce_to_object()?)
}

/// Get a JsBigInt from a BigInt.
pub(crate) fn get_js_big_int_from_big_int(env: Env, data: BigInt) -> Result<JsBigInt> {
    let (negative, words) = get_words_from_big_int(data);
    Ok(env.create_bigint_from_words(negative, words)?)
}

/// Helper for handling date/times with milliseconds
pub(crate) fn get_utc_date_time_from_asn1_milli<T: AsRef<[u8]>>(data: T) -> Result<DateTime<Utc>> {
    let mut decoder: rasn::ber::de::Decoder =
        rasn::ber::de::Decoder::new(data.as_ref(), rasn::ber::de::DecoderOptions::ber());

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

#[cfg(test)]
mod test {
    use chrono::{TimeZone, Utc};
    use num_bigint::BigInt;

    use super::get_words_from_big_int;
    use crate::utils::get_utc_date_time_from_asn1_milli;

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

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
use constants::{ASN1_NULL, ASN1_OBJECT_NAME_KEY, ASN1_OBJECT_TYPE_KEY, ASN1_OBJECT_VALUE_KEY};
use napi::{
    bindgen_prelude::{Array, Buffer},
    Env, JsBigInt, JsBuffer, JsNumber, JsObject, JsString, JsUnknown, ValueType,
};
use num_bigint::BigInt;
use thiserror::Error;

use objects::{
    ASN1BitString, ASN1Context, ASN1ContextTag, ASN1Object, ASN1Set, TypedObject, ASN1OID,
};
use types::{ASN1Data, JsValue};
use utils::{get_big_int_from_js, get_vec_from_js_unknown, get_words_from_big_int};

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
    #[error("The provided context is of an unknown format")]
    UknownContext,
    #[error("The provided ASN1 data is malformed and cannot be decoded")]
    MalformedData,
    #[error("Cannot decode bit string")]
    InvalidBitString,
    #[error("Can only handle Universal simple types for this operation")]
    InvalidSimpleTypesOnly,
    #[error("Context data must be a sequence")]
    InvalidContextNonSequence,
    #[error("Could not encode provided data into ASN.1 format")]
    InvalidDataEncoding,
}

/// Helper to convert a JS bigint to a JS Buffer
#[napi(strict, js_name = "BigIntToBuffer")]
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
#[napi(strict, js_name = "IntegerToBigInt")]
pub fn get_big_int_from_integer(env: Env, data: i64) -> Result<JsBigInt> {
    get_js_big_int_from_big_int(env, BigInt::from(data))
}

/// Helper to convert a JS string to a JS BigInt
#[napi(strict, js_name = "StringToBigInt")]
pub fn get_big_int_from_string(env: Env, data: String) -> Result<JsBigInt> {
    get_js_big_int_from_big_int(env, BigInt::from_str(&data)?)
}

/// Convert JS input into ASN1 BER encoded data.
#[napi(strict, js_name = "JStoASN1")]
pub fn js_to_asn1(
    #[napi(
        ts_arg_type = "BigInt | bigint | number | Date | ArrayBufferLike | Buffer | ASN1OID | ASN1Set | ASN1ContextTag | ASN1BitString | string | boolean | any[] | null"
    )]
    data: JsUnknown,
) -> Result<ASN1Encoder> {
    ASN1Encoder::js_new(data)
}

/// Convert ASN1 BER encoded data to JS native types.
/// This supports number arrays, Buffer, ArrayBufferLike, base64 or hex
/// encded strings, or null input.
#[napi(
    strict,
    js_name = "ASN1toJS",
    ts_return_type = "BigInt | bigint | number | Date  | Buffer | ASN1OID | ASN1Set | ASN1ContextTag | ASN1BitString | string | boolean | any[] | null"
)]
pub fn asn1_to_js(
    env: Env,
    #[napi(ts_arg_type = "string | null | number[] | Buffer | ArrayBuffer")] data: JsUnknown,
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
    ))
}

/// Get a JsUnknown from ASN1Data.
fn get_js_unknown_from_asn1_data(env: Env, data: ASN1Data) -> Result<JsUnknown> {
    JsUnknown::try_from(JsValue::try_from((env, data))?)
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
            obj.set_named_property::<JsString>(
                ASN1_OBJECT_VALUE_KEY,
                env.create_string(&val.value)?,
            )?;
        }
        ASN1Object::BitString(val) => {
            obj.set_named_property::<JsString>(
                ASN1_OBJECT_TYPE_KEY,
                env.create_string(ASN1BitString::TYPE)?,
            )?;
            obj.set_named_property::<JsBuffer>(
                ASN1_OBJECT_VALUE_KEY,
                ASN1BitString::new(env, val.into_vec()).value,
            )?;
        }
        ASN1Object::Context(val) => {
            obj.set_named_property::<JsString>(
                ASN1_OBJECT_TYPE_KEY,
                env.create_string(ASN1ContextTag::TYPE)?,
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

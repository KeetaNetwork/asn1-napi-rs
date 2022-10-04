#[macro_use]
extern crate napi_derive;

#[macro_use]
extern crate phf;

mod asn1;
mod constants;
mod objects;
mod types;
mod utils;

pub use crate::asn1::ASN1;

use anyhow::{bail, Result};
use constants::{ASN1_OBJECT_NAME_KEY, ASN1_OBJECT_TYPE_KEY, ASN1_OBJECT_VALUE_KEY};
use napi::{
    bindgen_prelude::Buffer, Env, JsBigInt, JsBuffer, JsNumber, JsObject, JsString, JsUnknown,
    ValueType,
};
use num_bigint::BigInt;
use rasn::ber::encode;
use thiserror::Error;

use objects::{ASN1BitString, ASN1Context, ASN1Object, ASN1Set, TypedObject, ASN1OID};
use types::{ASN1Data, JsValue};
use utils::{
    get_buffer_from_js, get_js_uknown_from_asn_data, get_string_from_js, get_vec_from_js,
    get_words_from_big_int,
};

/// Library errors
#[derive(Error, Eq, PartialEq, Debug)]
pub(crate) enum ASN1NAPIError {
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
    #[error("Cannot decoded Bitstring")]
    InvalidBitString,
    #[error("Can only handle Universal simple types for this operation")]
    InvalidSimpleTypesOnly,
    #[error("Context data must be a sequence")]
    InvalidContextNonSequence,
}

/// Helper to convert a JS BigInt to a JS Buffer
#[napi(strict, js_name = "ASN1BigIntToBuffer")]
pub fn asn1_big_int_to_buffer(mut data: JsBigInt) -> Result<Buffer> {
    Ok(data.get_i128()?.0.to_be_bytes().as_ref().into())
}

/// Helper to convert a JS number to a JS BigInt
#[napi(strict, js_name = "ASN1IntegerToBigInt")]
pub fn asn1_integer_to_big_int(env: Env, data: i64) -> Result<JsBigInt> {
    let (bit, words) = get_words_from_big_int(BigInt::from(data));
    Ok(env.create_bigint_from_words(bit, words)?)
}

/// Convert JS input into ASN1 BER encoded data.
#[napi(strict, js_name = "JStoASN1")]
pub fn js_to_asn1(data: JsUnknown) -> Result<Vec<u8>> {
    if let Ok(data) = encode(&ASN1Data::try_from(data)?) {
        Ok(data)
    } else {
        bail!(ASN1NAPIError::UnknownJsArgument)
    }
}

/// Convert ASN1 BER encoded data to JS native types.
#[napi(strict, js_name = "ASN1toJS")]
pub fn asn1_to_js(env: Env, data: JsUnknown) -> Result<JsUnknown> {
    let asn1 = match data.get_type()? {
        ValueType::String => ASN1::try_from(data.coerce_to_string()?.into_utf8()?.as_str()?)?,
        ValueType::Object if data.is_array()? => ASN1::new(get_vec_from_js(data)?),
        ValueType::Object if data.is_buffer()? => ASN1::new(get_buffer_from_js(data)?),
        _ => bail!(ASN1NAPIError::UnknownJsArgument),
    };

    asn1_data_to_js_unknown(env, ASN1Data::try_from(asn1)?)
}

/// Get a JSUnknown from an ASN1 object.
fn asn1_data_to_js_unknown(env: Env, data: ASN1Data) -> Result<JsUnknown> {
    JsUnknown::try_from(JsValue::try_from((env, data))?)
}

/// Get a Vec<ASN1Data> from a JsUnknown.
fn get_array_from_js(data: JsUnknown) -> Result<Vec<ASN1Data>> {
    let obj = data.coerce_to_object()?;
    let len = obj.get_array_length()?;
    let mut result = Vec::new();

    for i in 0..len {
        result.push(ASN1Data::try_from(obj.get_element::<JsUnknown>(i)?)?);
    }

    Ok(result)
}

/// Get an ASN1Object from a JsUnknown.
fn get_object_from_js(data: JsUnknown) -> Result<ASN1Object> {
    let obj = data.coerce_to_object()?;
    let field = obj.get_named_property::<JsUnknown>(ASN1_OBJECT_TYPE_KEY)?;

    if let Ok(ValueType::String) = field.get_type() {
        let name = get_string_from_js(field)?;

        Ok(match name.as_str() {
            ASN1OID::TYPE => ASN1Object::Oid(ASN1OID::try_from(obj)?),
            ASN1BitString::TYPE => ASN1Object::BitString(ASN1BitString::try_from(obj)?),
            ASN1Set::TYPE => ASN1Object::Set(ASN1Set::try_from(obj)?),
            ASN1Context::TYPE => ASN1Object::Context(ASN1Context::try_from(obj)?),
            _ => bail!(ASN1NAPIError::UnknownFieldProperty),
        })
    } else {
        bail!(ASN1NAPIError::UnknownObject)
    }
}

/// Get a JsObject from an ANS1Object.
/// Note: Wrapping native objects results in empty JS objects.
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
                env.create_buffer_with_data(val.value)?.into_raw(),
            )?;
        }
        ASN1Object::Context(val) => {
            if let Ok(contents) = ASN1Data::try_from(*val.contains) {
                obj.set_named_property::<JsString>(
                    ASN1_OBJECT_TYPE_KEY,
                    env.create_string(ASN1Context::TYPE)?,
                )?;
                obj.set_named_property::<JsNumber>(
                    ASN1_OBJECT_VALUE_KEY,
                    env.create_uint32(val.value)?,
                )?;
                obj.set_named_property::<JsUnknown>(
                    "contains",
                    get_js_uknown_from_asn_data(env, contents)?,
                )?;
            } else {
                bail!(ASN1NAPIError::InvalidContextNonSequence)
            }
        }
    };

    Ok(obj)
}

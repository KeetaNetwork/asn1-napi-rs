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
use napi::{bindgen_prelude::Buffer, Env, JsBigInt, JsObject, JsString, JsUnknown, ValueType};
use rasn::ber::encode;
use thiserror::Error;

use constants::*;
use objects::{ASN1BitString, ASN1ContextTag, ASN1Object, ASN1Set, ASN1OID};
use types::{ASN1Data, ASN1Number, JsType};
use utils::{
    get_big_integer_from_js, get_boolean_from_js, get_buffer_from_js, get_fixed_date_time_from_js,
    get_integer_from_js, get_string_from_js, get_vec_from_js, get_words_from_big_int,
};

/// Library errors
#[derive(Error, Eq, PartialEq, Debug)]
pub(crate) enum ASN1NAPIError {
    #[error("Unable to handle JS input type")]
    UnknownArgument,
    #[error("Unable to handle this object")]
    UnknownObject,
    #[error("Unable to handle this objects type field")]
    UnknownFieldProperty,
    #[error("Unable to handle this OID")]
    UnknownOid,
    #[error("The provided string is of an unknown format")]
    UnknownStringFormat,
    #[error("The provided ASN1 data is malformed and cannot be decoded")]
    MalformedData,
    #[error("Cannot decoded Bitstring")]
    InvalidBitString,
}

/// Helper to convert a JS BigInt to a JS Buffer
#[napi(strict, js_name = "ASN1BigIntToBuffer")]
pub fn asn1_big_int_to_buffer(mut data: JsBigInt) -> Result<Buffer> {
    Ok(data.get_i128()?.0.to_be_bytes().as_ref().into())
}

/// Helper to convert a JS number to a JS BigInt
#[napi(strict, js_name = "ASN1IntegerToBigInt")]
pub fn asn1_integer_to_big_int(data: i64) -> Result<i128> {
    Ok(data as i128)
}

/// Convert JS input into ASN1 BER encoded data.
#[napi(strict, js_name = "JStoASN1")]
pub fn js_to_asn1(data: JsUnknown) -> Result<Vec<u8>> {
    if let Ok(data) = encode(&get_asn1_data_from_unknown(data)?) {
        Ok(data)
    } else {
        bail!(ASN1NAPIError::UnknownArgument)
    }
}

/// Convert ASN1 BER encoded data to JS native types.
#[napi(strict, js_name = "ASN1toJS")]
pub fn asn1_to_js(env: Env, data: JsUnknown) -> Result<JsUnknown> {
    let asn1 = match data.get_type()? {
        ValueType::String => ASN1::try_from(data.coerce_to_string()?.into_utf8()?.as_str()?)?,
        ValueType::Object if data.is_array()? => ASN1::new(get_vec_from_js(data)?)?,
        ValueType::Object if data.is_buffer()? => ASN1::new(get_buffer_from_js(data)?)?,
        _ => bail!(ASN1NAPIError::UnknownArgument),
    };

    asn1_to_js_unknown(env, asn1)
}

/// Get a JSUnknown from an ASN1 object.
fn asn1_to_js_unknown(env: Env, asn1: ASN1) -> Result<JsUnknown> {
    Ok(match asn1.get_js_type() {
        JsType::Integer => match ASN1Number::try_from(asn1)? {
            ASN1Number::Integer(val) => {
                env.create_bigint_from_i64(val)?.into_unknown()?
                //env.create_int64(val)?.into_unknown()
            }
            ASN1Number::BigInt(val) => {
                let (bit, words) = get_words_from_big_int(val);
                env.create_bigint_from_words(bit, words)?.into_unknown()?
            }
        },
        JsType::DateTime => env
            .create_date(asn1.into_date()?.timestamp_micros() as f64)?
            .into_unknown(),
        JsType::String => env
            .create_string_from_std(asn1.into_string()?)?
            .into_unknown(),
        JsType::BitString => env
            .create_external(asn1.into_bitstring()?, None)?
            .into_unknown(),
        JsType::Boolean => env.get_boolean(asn1.into_bool()?)?.into_unknown(),
        JsType::Buffer => env
            .create_buffer_with_data(asn1.into_buffer()?.to_vec())?
            .into_unknown(),
        JsType::Object => {
            //let mut js_object = env.create_object()?;
            //
            // match asn1.into_object()? {
            //     ASN1Object::ASN1OID(obj) => env.wrap(&mut js_object, obj),
            //     ASN1Object::ASN1Set(obj) => env.wrap(&mut js_object, obj),
            //     ASN1Object::ASN1BitString(obj) => env.wrap(&mut js_object, obj),
            //     ASN1Object::ASN1ContextTag(obj) => env.wrap(&mut js_object, obj),
            // }?;

            get_object_from_asn1(env, asn1)?.into_unknown()
        }
        JsType::Sequence => asn1.into_array(env)?.coerce_to_object()?.into_unknown(),
        _ => env.get_null()?.into_unknown(),
    })
}

/// Get a Vec<ASN1Data> from a JsUnknown.
fn get_array_from_js(data: JsUnknown) -> Result<Vec<ASN1Data>> {
    let obj = data.coerce_to_object()?;
    let len = obj.get_array_length()?;
    let mut result = Vec::new();

    for i in 0..len {
        result.push(get_asn1_data_from_unknown(
            obj.get_element::<JsUnknown>(i)?,
        )?);
    }

    Ok(result)
}

/// Convert a JsUnknown to a known ASN1Data type.
fn get_asn1_data_from_unknown(data: JsUnknown) -> Result<ASN1Data> {
    Ok(match data.get_type()? {
        ValueType::Boolean => ASN1Data::Bool(get_boolean_from_js(data)?),
        ValueType::BigInt => ASN1Data::BigInt(get_big_integer_from_js(data)?),
        ValueType::Number => ASN1Data::Int(get_integer_from_js(data)?),
        ValueType::String => ASN1Data::String(get_string_from_js(data)?),
        ValueType::Object if data.is_buffer()? => ASN1Data::Bytes(get_buffer_from_js(data)?),
        ValueType::Object if data.is_date()? => ASN1Data::Date(get_fixed_date_time_from_js(data)?),
        ValueType::Object if data.is_array()? => ASN1Data::Array(get_array_from_js(data)?),
        ValueType::Object => {
            let obj = get_object_from_js(data)?;
            ASN1Data::Object(obj)
        }
        _ => ASN1Data::Unknown,
    })
}

/// Get an ASN1Object from a JsUnknown.
fn get_object_from_js(data: JsUnknown) -> Result<ASN1Object> {
    let obj = data.coerce_to_object()?;
    let field = obj.get_named_property::<JsUnknown>("type")?;

    if let Ok(ValueType::String) = field.get_type() {
        let name = get_string_from_js(field)?;

        Ok(match name.as_str() {
            ASN1_OBJECT_TYPE_OID => ASN1Object::ASN1OID(ASN1OID::try_from(obj)?),
            ASN1_OBJECT_TYPE_BITSTRING => ASN1Object::ASN1BitString(ASN1BitString::try_from(obj)?),
            ASN1_OBJECT_TYPE_SET => ASN1Object::ASN1Set(ASN1Set::try_from(obj)?),
            ASN1_OBJECT_TYPE_CONTEXT => ASN1Object::ASN1ContextTag(ASN1ContextTag::try_from(obj)?),
            _ => bail!(ASN1NAPIError::UnknownFieldProperty),
        })
    } else {
        bail!(ASN1NAPIError::UnknownObject)
    }
}

// TODO Make less bootleg - wrapping results in empty objects...
fn get_object_from_asn1(env: Env, asn1: ASN1) -> Result<JsObject> {
    let mut js_object = env.create_object()?;

    match asn1.into_object()? {
        ASN1Object::ASN1OID(obj) => {
            js_object
                .set_named_property::<JsString>("type", env.create_string(ASN1_OBJECT_TYPE_OID)?)?;
            js_object.set_named_property::<JsString>("oid", env.create_string(&obj.oid)?)?;
        }
        ASN1Object::ASN1Set(obj) => {
            let mut oid = env.create_object()?;

            oid.set_named_property::<JsString>("type", env.create_string(ASN1_OBJECT_TYPE_OID)?)?;
            oid.set_named_property::<JsString>("oid", env.create_string(&obj.name.oid)?)?;

            js_object
                .set_named_property::<JsString>("type", env.create_string(ASN1_OBJECT_TYPE_SET)?)?;
            js_object.set_named_property::<JsObject>("name", oid)?;
            js_object.set_named_property::<JsString>("value", env.create_string(&obj.value)?)?;
        }
        ASN1Object::ASN1BitString(obj) => {
            js_object.set_named_property::<JsString>(
                "type",
                env.create_string(ASN1_OBJECT_TYPE_BITSTRING)?,
            )?;
            js_object.set_named_property::<JsUnknown>(
                "value",
                env.create_buffer_with_data(obj.value)?.into_unknown(),
            )?;
        }
        ASN1Object::ASN1ContextTag(_obj) => {
            js_object.set_named_property::<JsString>(
                "type",
                env.create_string(ASN1_OBJECT_TYPE_CONTEXT)?,
            )?;
            todo!()
        }
    };

    Ok(js_object)
}

#[cfg(test)]
mod test {}

use anyhow::{bail, Error, Result};
use chrono::{DateTime, FixedOffset};
use napi::{
    Env, JsBigInt, JsBoolean, JsBuffer, JsDate, JsNull, JsNumber, JsObject, JsString, JsUndefined,
    JsUnknown, ValueType,
};
use num_bigint::BigInt;
use rasn::{
    types::{Any, Class, Implicit, ObjectIdentifier, OctetString, Open},
    AsnType, Decode, Tag,
};

use crate::{
    asn1::{ASN1Decoder, ASN1Iterator},
    get_big_int_from_integer, get_js_big_int_from_big_int, get_js_obj_from_asn1_data,
    get_js_obj_from_asn1_object,
    objects::{ASN1Object, ASN1RawBitString, ASN1OID},
    utils::{
        get_array_from_js, get_big_int_from_js, get_boolean_from_js, get_buffer_from_js,
        get_fixed_date_from_js, get_integer_from_js, get_string_from_js, get_utf16_from_string,
    },
    ASN1NAPIError,
};

/// JavaScript Types
#[derive(Hash, Eq, Copy, Clone, PartialEq, Debug)]
pub enum JsType {
    Boolean,
    Integer,
    BigInt,
    String,
    Buffer,
    Sequence,
    Object,
    DateTime,
    Null,
    Unknown,
    Undefined,
}

/// JavaScript Values Container
pub enum JsValue {
    Boolean(JsBoolean),
    Integer(JsNumber),
    BigInt(JsBigInt),
    String(JsString),
    Buffer(JsBuffer),
    Sequence(JsObject),
    Object(JsObject),
    DateTime(JsDate),
    Null(JsNull),
    Unknown(JsUnknown),
    Undefined(JsUndefined),
}

#[derive(AsnType, Clone, Decode, Debug, Eq, PartialEq)]
#[rasn(choice)]
#[rasn(automatic_tags)]
pub enum ASN1Data {
    Boolean(bool),
    Integer(i64),
    BigInt(BigInt),
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<ASN1Data>),
    Object(ASN1Object),
    Date(DateTime<FixedOffset>),
    Unknown(Any),
    #[rasn(tag(universal, 5))]
    Null,
}

/// Integer or Big Integer
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum ASN1Number {
    Integer(i64),
    BigInt(BigInt),
}

impl From<Tag> for JsType {
    fn from(tag: Tag) -> Self {
        match tag {
            Tag::BOOL => JsType::Boolean,
            Tag::INTEGER => JsType::Integer,
            Tag::NULL => JsType::Null,
            Tag::UTF8_STRING => JsType::String,
            Tag::PRINTABLE_STRING => JsType::String,
            Tag::VISIBLE_STRING => JsType::String,
            Tag::UNIVERSAL_STRING => JsType::String,
            Tag::GENERAL_STRING => JsType::String,
            Tag::GRAPHIC_STRING => JsType::String,
            Tag::IA5_STRING => JsType::String,
            Tag::VIDEOTEX_STRING => JsType::String,
            Tag::TELETEX_STRING => JsType::String,
            Tag::NUMERIC_STRING => JsType::String,
            Tag::BMP_STRING => JsType::String,
            Tag::BIT_STRING => JsType::Object,
            Tag::OCTET_STRING => JsType::Buffer,
            Tag::SEQUENCE => JsType::Sequence,
            Tag::GENERALIZED_TIME => JsType::DateTime,
            Tag::UTC_TIME => JsType::DateTime,
            Tag::OBJECT_IDENTIFIER => JsType::Object,
            Tag::SET => JsType::Object,
            context => match context.class {
                Class::Context => JsType::Object,
                Class::Universal => JsType::Unknown,
                Class::Application => todo!(),
                Class::Private => todo!(),
            },
        }
    }
}

impl TryFrom<ASN1Decoder> for ASN1Data {
    type Error = Error;

    fn try_from(value: ASN1Decoder) -> Result<Self, Self::Error> {
        Ok(match value.get_js_type() {
            JsType::Boolean => ASN1Data::Boolean(value.into_bool()?),
            JsType::Integer => ASN1Data::try_from(ASN1Number::try_from(value)?)?,
            JsType::BigInt => ASN1Data::BigInt(value.into_big_integer()?),
            JsType::String => ASN1Data::String(value.into_string()?),
            JsType::Buffer => ASN1Data::Bytes(value.into_bytes()?),
            JsType::Sequence => ASN1Data::Array(Vec::<ASN1Data>::try_from(&value.into_iter())?),
            JsType::Object => ASN1Data::Object(value.into_object()?),
            JsType::DateTime => ASN1Data::Date(DateTime::<FixedOffset>::from(value.into_date()?)),
            JsType::Unknown => ASN1Data::Unknown(value.into_any()?),
            JsType::Undefined | JsType::Null => ASN1Data::Null,
        })
    }
}

impl TryFrom<&Open> for ASN1Data {
    type Error = Error;

    fn try_from(data: &Open) -> Result<Self, Self::Error> {
        Ok(match data.to_owned() {
            Open::BmpString(data) => ASN1Data::String(data.to_string()),
            Open::Bool(data) => ASN1Data::Boolean(data),
            Open::GeneralizedTime(data) => ASN1Data::Date(data),
            Open::Ia5String(data) => ASN1Data::String(data.to_string()),
            Open::Integer(data) => ASN1Data::BigInt(data),
            Open::OctetString(data) => ASN1Data::Bytes(data.to_vec()),
            Open::PrintableString(data) => ASN1Data::String(data.to_string()),
            Open::UniversalString(data) => ASN1Data::String(data.to_string()),
            Open::UtcTime(data) => ASN1Data::Date(DateTime::<FixedOffset>::from(data)),
            Open::VisibleString(data) => ASN1Data::String(data.to_string()),
            Open::InstanceOf(data) => ASN1Data::try_from(data.value)?,
            Open::BitString(data) => {
                ASN1Data::Object(ASN1Object::BitString(ASN1RawBitString::new(data)))
            }
            Open::ObjectIdentifier(data) => {
                ASN1Data::Object(ASN1Object::Oid(ASN1OID::try_from(data.to_vec())?))
            }
            Open::Null => ASN1Data::Null,
        })
    }
}

impl TryFrom<Open> for ASN1Data {
    type Error = Error;

    fn try_from(data: Open) -> Result<Self, Self::Error> {
        Self::try_from(&data)
    }
}

impl TryFrom<JsUnknown> for ASN1Data {
    type Error = Error;

    fn try_from(value: JsUnknown) -> Result<Self, Self::Error> {
        Ok(match value.get_type()? {
            ValueType::Null => ASN1Data::Null,
            ValueType::Boolean => ASN1Data::Boolean(get_boolean_from_js(value)?),
            ValueType::BigInt => ASN1Data::BigInt(get_big_int_from_js(value)?),
            ValueType::Number => ASN1Data::Integer(get_integer_from_js(value)?),
            ValueType::String => ASN1Data::String(get_string_from_js(value)?),
            ValueType::Object if value.is_buffer()? => ASN1Data::Bytes(get_buffer_from_js(value)?),
            ValueType::Object if value.is_date()? => ASN1Data::Date(get_fixed_date_from_js(value)?),
            ValueType::Object if value.is_array()? => ASN1Data::Array(get_array_from_js(value)?),
            ValueType::Object => ASN1Data::Object(ASN1Object::try_from(value)?),
            _ => ASN1Data::Unknown(Any::new(get_buffer_from_js(value)?)),
        })
    }
}

impl TryFrom<ASN1Number> for ASN1Data {
    type Error = Error;

    fn try_from(value: ASN1Number) -> Result<Self, Self::Error> {
        Ok(match value {
            ASN1Number::Integer(val) => ASN1Data::Integer(val),
            ASN1Number::BigInt(val) => ASN1Data::BigInt(val),
        })
    }
}

impl TryFrom<&ASN1Iterator> for Vec<ASN1Data> {
    type Error = Error;

    fn try_from(value: &ASN1Iterator) -> Result<Self, Self::Error> {
        value.to_owned().collect()
    }
}

impl TryFrom<&ASN1Data> for Open {
    type Error = Error;

    fn try_from(data: &ASN1Data) -> Result<Self, Self::Error> {
        Ok(match data.to_owned() {
            ASN1Data::Boolean(data) => Open::Bool(data),
            ASN1Data::Integer(data) => Open::Integer(BigInt::from(data)),
            ASN1Data::BigInt(data) => Open::Integer(data),
            ASN1Data::String(data) => Open::PrintableString(Implicit::new(data)),
            ASN1Data::Bytes(data) => Open::OctetString(OctetString::from(data)),
            ASN1Data::Date(data) => Open::GeneralizedTime(data),
            ASN1Data::Object(data) => match data {
                ASN1Object::BitString(data) => Open::BitString(data.into()),
                ASN1Object::Oid(data) => Open::ObjectIdentifier(ObjectIdentifier::try_from(data)?),
                _ => bail!(ASN1NAPIError::InvalidSimpleTypesOnly),
            },
            ASN1Data::Null => Open::Null,
            _ => bail!(ASN1NAPIError::InvalidSimpleTypesOnly),
        })
    }
}

impl TryFrom<ASN1Data> for Open {
    type Error = Error;

    fn try_from(data: ASN1Data) -> Result<Self, Self::Error> {
        Self::try_from(&data)
    }
}

impl TryFrom<(Env, ASN1Data)> for JsValue {
    type Error = Error;

    fn try_from(value: (Env, ASN1Data)) -> Result<Self, Self::Error> {
        let (env, data) = value;

        Ok(match data {
            ASN1Data::Boolean(val) => JsValue::Boolean(env.get_boolean(val)?),
            //ASN1Data::Integer(val) => JsValue::Integer(env.create_int64(val)?),
            ASN1Data::Integer(val) => JsValue::BigInt(get_big_int_from_integer(env, val)?),
            ASN1Data::BigInt(val) => JsValue::BigInt(get_js_big_int_from_big_int(env, val)?),
            ASN1Data::String(val) => {
                JsValue::String(env.create_string_utf16(get_utf16_from_string(val).as_ref())?)
            }
            ASN1Data::Bytes(val) => JsValue::Buffer(env.create_buffer_with_data(val)?.into_raw()),
            ASN1Data::Date(val) => {
                JsValue::DateTime(env.create_date(val.timestamp_millis() as f64)?)
            }
            ASN1Data::Unknown(val) => JsValue::Unknown(
                env.create_arraybuffer_with_data(val.into_bytes())?
                    .into_unknown(),
            ),
            ASN1Data::Array(val) => {
                JsValue::Sequence(get_js_obj_from_asn1_data(env, val.into_iter())?)
            }
            ASN1Data::Object(val) => JsValue::Object(get_js_obj_from_asn1_object(env, val)?),
            ASN1Data::Null => JsValue::Null(env.get_null()?),
        })
    }
}

impl TryFrom<JsValue> for JsUnknown {
    type Error = Error;

    fn try_from(value: JsValue) -> Result<Self, Self::Error> {
        Ok(match value {
            JsValue::Boolean(val) => val.into_unknown(),
            JsValue::Integer(val) => val.into_unknown(),
            JsValue::BigInt(val) => val.into_unknown()?,
            JsValue::String(val) => val.into_unknown(),
            JsValue::Buffer(val) => val.into_unknown(),
            JsValue::Sequence(val) => val.into_unknown(),
            JsValue::Object(val) => val.into_unknown(),
            JsValue::DateTime(val) => val.into_unknown(),
            JsValue::Null(val) => val.into_unknown(),
            JsValue::Unknown(val) => val.into_unknown(),
            JsValue::Undefined(val) => val.into_unknown(),
        })
    }
}

impl TryFrom<ASN1Decoder> for ASN1Number {
    type Error = Error;

    /// Attempt to decode a number as an ASN1Number from an ASN1 instance.
    fn try_from(value: ASN1Decoder) -> Result<Self, Self::Error> {
        if let Ok(num) = value.into_integer() {
            Ok(ASN1Number::Integer(num))
        } else if let Ok(num) = value.into_big_integer() {
            Ok(ASN1Number::BigInt(num))
        } else {
            bail!(ASN1NAPIError::MalformedData)
        }
    }
}

#[cfg(test)]
mod test {
    use num_bigint::BigInt;

    use crate::{types::ASN1Number, ASN1Decoder};

    #[test]
    fn test_asn1number_try_from_asn1() {
        let asn1 = ASN1Decoder::new(vec![2, 1, 42]);
        let input = ASN1Number::try_from(asn1).unwrap();

        assert_eq!(input, ASN1Number::Integer(42));

        let asn1 = ASN1Decoder::new(vec![2, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let input = ASN1Number::try_from(asn1).unwrap();

        assert_eq!(
            input,
            ASN1Number::BigInt(BigInt::from(18591708106338011145_i128))
        );
    }
}

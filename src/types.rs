use anyhow::{bail, Error, Result};
use chrono::{DateTime, FixedOffset};
use napi::{
    Env, JsBigInt, JsBoolean, JsBuffer, JsDate, JsNull, JsNumber, JsObject, JsString, JsUndefined,
    JsUnknown, ValueType,
};
use num_bigint::BigInt;
use rasn::{types::Any, AsnType, Decode, Encode, Tag};

use crate::{
    asn1::{ASNIterator, ASN1},
    asn1_integer_to_big_int, get_array_from_js, get_js_obj_from_asn_object, get_object_from_js,
    objects::ASN1Object,
    utils::{
        get_big_int_from_js, get_boolean_from_js, get_buffer_from_js, get_fixed_date_from_js,
        get_integer_from_js, get_js_big_int_from_big_int, get_js_obj_from_asn_data,
        get_string_from_js,
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
pub enum ASN1Data {
    #[rasn(tag(1))]
    Boolean(bool),
    #[rasn(tag(2))]
    Integer(i64),
    #[rasn(tag(3))]
    BigInt(BigInt),
    #[rasn(tag(4))]
    String(String),
    #[rasn(tag(5))]
    Bytes(Vec<u8>),
    #[rasn(tag(6))]
    Array(Vec<ASN1Data>),
    #[rasn(tag(7))]
    Object(ASN1Object),
    #[rasn(tag(8))]
    Date(DateTime<FixedOffset>),
    #[rasn(tag(9))]
    Unknown(Any),
    #[rasn(tag(10))]
    Null,
}

/// TODO
/// ASN1 Application contexts
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
#[rasn(choice)]
pub enum ASN1Contexts {
    #[rasn(tag(0))]
    A(Vec<Any>),
}

/// Integer or Big Integer
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum ASN1Number {
    Integer(i64),
    BigInt(BigInt),
}

/// TODO Native encoding without ASN1 dependencies
// #[derive(Hash, Eq, PartialEq, Debug)]
// pub enum UniversalTag {
//     Boolean = 0x01,     // +
//     Integer = 0x02,     // +
//     BitString = 0x03,   // +
//     OctetString = 0x04, // +
//     Null = 0x05,        // +
//     ObjectID = 0x06,    // +
//     ObjectDescriptor = 0x07,
//     External = 0x08,
//     Real = 0x09,
//     Enumerated = 0xA,
//     EmbeddedPDV = 0xB,
//     UTF8String = 0xC, // +
//     RelativeObjectID = 0xD,
//     Sequence = 0x10,        // +
//     Set = 0x11,             // +
//     NumericString = 0x12,   // +
//     PrintableString = 0x13, // +
//     TelexString = 0x14,     // +
//     VideotexString = 0x15,  // +
//     IA5String = 0x16,       // +
//     UTCTime = 0x17,         // +
//     GeneralizedTime = 0x18, // +
//     GraphicString = 0x19,   // +
//     VisibleString = 0x1A,   // +
//     GeneralString = 0x1B,   // +
//     UniversalString = 0x1C, // +
//     ChracterString = 0x1D,  // +
//     BMPString = 0x1E,       // +
// }

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
            _ => JsType::Unknown,
        }
    }
}

impl From<ASN1Data> for Vec<ASN1Data> {
    fn from(data: ASN1Data) -> Self {
        match data {
            ASN1Data::Array(data) => data,
            data => vec![data],
        }
    }
}

impl From<Vec<ASN1Data>> for ASN1Data {
    fn from(data: Vec<ASN1Data>) -> Self {
        match data.get(0) {
            Some(ASN1Data::Array(x)) if x.len() == 1 => ASN1Data::Array(x.to_owned()),
            Some(x) if data.len() == 1 => x.to_owned(),
            None => ASN1Data::Null,
            _ => ASN1Data::Array(data),
        }
    }
}

impl TryFrom<&ASNIterator> for Vec<ASN1Data> {
    type Error = Error;

    fn try_from(value: &ASNIterator) -> Result<Self, Self::Error> {
        value.to_owned().collect()
    }
}

impl TryFrom<ASN1> for ASN1Data {
    type Error = Error;

    fn try_from(value: ASN1) -> Result<Self, Self::Error> {
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

impl TryFrom<(Env, ASN1Data)> for JsValue {
    type Error = Error;

    fn try_from(value: (Env, ASN1Data)) -> Result<Self, Self::Error> {
        let (env, data) = value;

        Ok(match data {
            ASN1Data::Boolean(val) => JsValue::Boolean(env.get_boolean(val)?),
            //ASN1Data::Integer(val) => JsValue::Integer(env.create_int64(val)?),
            ASN1Data::Integer(val) => JsValue::BigInt(asn1_integer_to_big_int(env, val)?),
            ASN1Data::BigInt(val) => JsValue::BigInt(get_js_big_int_from_big_int(env, val)?),
            ASN1Data::String(val) => JsValue::String(env.create_string(val.as_str())?),
            ASN1Data::Bytes(val) => JsValue::Buffer(env.create_buffer_with_data(val)?.into_raw()),
            ASN1Data::Date(val) => {
                JsValue::DateTime(env.create_date(val.timestamp_millis() as f64)?)
            }
            ASN1Data::Unknown(val) => JsValue::Unknown(
                env.create_arraybuffer_with_data(val.into_bytes())?
                    .into_unknown(),
            ),
            ASN1Data::Array(val) => JsValue::Sequence(get_js_obj_from_asn_data(env, val)?),
            ASN1Data::Object(val) => JsValue::Object(get_js_obj_from_asn_object(env, val)?),
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

impl TryFrom<JsUnknown> for ASN1Data {
    type Error = Error;

    fn try_from(value: JsUnknown) -> Result<Self, Self::Error> {
        Ok(match value.get_type()? {
            ValueType::Boolean => ASN1Data::Boolean(get_boolean_from_js(value)?),
            ValueType::BigInt => ASN1Data::BigInt(get_big_int_from_js(value)?),
            ValueType::Number => ASN1Data::Integer(get_integer_from_js(value)?),
            ValueType::String => ASN1Data::String(get_string_from_js(value)?),
            ValueType::Object if value.is_buffer()? => ASN1Data::Bytes(get_buffer_from_js(value)?),
            ValueType::Object if value.is_date()? => ASN1Data::Date(get_fixed_date_from_js(value)?),
            ValueType::Object if value.is_array()? => ASN1Data::Array(get_array_from_js(value)?),
            ValueType::Object => ASN1Data::Object(get_object_from_js(value)?),
            _ => ASN1Data::Unknown(Any::new(get_buffer_from_js(value)?)),
        })
    }
}

impl TryFrom<ASN1> for ASN1Number {
    type Error = Error;

    /// Attempt to decode a number as an ASN1Number from an ASN1 instance.
    fn try_from(value: ASN1) -> Result<Self, Self::Error> {
        if let Ok(num) = value.into_integer() {
            Ok(ASN1Number::Integer(num))
        } else if let Ok(num) = value.into_big_integer() {
            Ok(ASN1Number::BigInt(num))
        } else {
            bail!(ASN1NAPIError::MalformedData)
        }
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

#[cfg(test)]
mod test {
    use num_bigint::BigInt;

    use crate::{types::ASN1Number, ASN1};

    #[test]
    fn test_asn1number_try_from_asn1() {
        let asn1 = ASN1::new(vec![2, 1, 42]);
        let input = ASN1Number::try_from(asn1).unwrap();

        assert_eq!(input, ASN1Number::Integer(42));

        let asn1 = ASN1::new(vec![2, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let input = ASN1Number::try_from(asn1).unwrap();

        assert_eq!(
            input,
            ASN1Number::BigInt(BigInt::from(18591708106338011145_i128))
        );
    }
}

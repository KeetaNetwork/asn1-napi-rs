#[macro_use]
extern crate napi_derive;

#[macro_use]
extern crate phf;

use std::str::FromStr;

use anyhow::{bail, Error, Result};
use chrono::{DateTime, FixedOffset, NaiveDateTime, Utc};
use napi::{
    bindgen_prelude::{Array, Buffer, FromNapiValue},
    Env, JsBigInt, JsBoolean, JsBuffer, JsDate, JsNumber, JsObject, JsString, JsUnknown, ValueType,
};
use num_bigint::{BigInt, Sign};
use rasn::{
    ber::{decode, encode},
    de::Error as rasnError,
    enc::Error as RASNError,
    types::{
        Any, BitString, Class, ObjectIdentifier, OctetString, Oid, PrintableString, SequenceOf,
        Utf8String,
    },
    AsnType, Decode, Decoder, Encode, Encoder, Tag,
};
use thiserror::Error;

const ASN1_OBJECT_VALUE_KEY: &str = "value";
const ASN1_OBJECT_TYPE_BITSTRING: &str = "bitstring";
const ASN1_OBJECT_TYPE_OID: &str = "oid";
const ASN1_OBJECT_TYPE_SET: &str = "set";
const ASN1_OBJECT_TYPE_CONTEXT: &str = "context";
const ASN1_OBJECT_TYPE_UNKNOWN: &str = "unknown";

/// Library errors
#[derive(Error, Eq, PartialEq, Debug)]
enum ASN1NAPIError {
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

/// TODO Native encoding without ASN1 dependencies
#[derive(Hash, Eq, PartialEq, Debug)]
pub enum UniversalTag {
    Boolean = 0x01,     // +
    Integer = 0x02,     // +
    BitString = 0x03,   // +
    OctetString = 0x04, // +
    Null = 0x05,        // +
    ObjectID = 0x06,    // +
    ObjectDescriptor = 0x07,
    External = 0x08,
    Real = 0x09,
    Enumerated = 0xA,
    EmbeddedPDV = 0xB,
    UTF8String = 0xC, // +
    RelativeObjectID = 0xD,
    Sequence = 0x10,        // +
    Set = 0x11,             // +
    NumericString = 0x12,   // +
    PrintableString = 0x13, // +
    TelexString = 0x14,     // +
    VideotexString = 0x15,  // +
    IA5String = 0x16,       // +
    UTCTime = 0x17,         // +
    GeneralizedTime = 0x18, // +
    GraphicString = 0x19,   // +
    VisibleString = 0x1A,   // +
    GeneralString = 0x1B,   // +
    UniversalString = 0x1C, // +
    ChracterString = 0x1D,  // +
    BMPString = 0x1E,       // +
}

/// JavaScript Types
#[derive(Hash, Eq, PartialEq, Debug)]
pub enum JsType {
    Sequence,
    Integer,
    DateTime,
    Null,
    String,
    BitString,
    Boolean,
    Buffer,
    Object,
    Unknown,
    Undefined,
}

#[derive(Debug, Eq, PartialEq)]
pub enum ASN1Data {
    Bool(bool),
    BigInt(BigInt),
    Int(i64),
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<ASN1Data>),
    Date(DateTime<FixedOffset>),
    Object(ASN1Object),
    Unknown,
}

#[derive(Debug, Eq, PartialEq)]
pub enum ASN1Object {
    ASN1OID(ASN1OID),
    ASN1Set(ASN1Set),
    ASN1BitString(ASN1BitString),
    ASN1ContextTag(ASN1ContextTag),
}

/// Valid ASN1Object Types
#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub enum ASN1ObjectType {
    BitString,
    Oid,
    Set,
    Context,
    Unknown,
}

/// Integer or Big Integer
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum ASN1Number {
    Integer(i64),
    BigInt(BigInt),
}

/// Convert ASN1 BER encoded data to JS native types.
#[napi(js_name = "Asn1")]
#[derive(Hash, Eq, PartialEq, Debug)]
pub struct ASN1 {
    js_type: JsType,
    data: Vec<u8>,
}

/// ANS1 OID.
#[napi(object, js_name = "ASN1OID")]
#[derive(Hash, Eq, PartialEq, Debug)]
pub struct ASN1OID {
    pub r#type: &'static str,
    pub oid: String,
}

/// ANS1 Set.
#[napi(object, js_name = "ASN1Set")]
#[derive(Hash, Eq, PartialEq, Debug)]
pub struct ASN1Set {
    pub r#type: &'static str,
    pub name: ASN1OID,
    pub value: String,
}

/// ANS1 Context Tag.
#[napi(object, js_name = "ASN1ContextTag")]
#[derive(Hash, Eq, PartialEq, Debug)]
pub struct ASN1ContextTag {
    pub r#type: &'static str,
    pub value: i64,
    pub data: Vec<u8>,
}

/// ANS1 bitstring.
#[napi(object, js_name = "ASN1BitString")]
#[derive(Hash, Eq, PartialEq, Debug)]
pub struct ASN1BitString {
    pub r#type: &'static str,
    pub value: Vec<u8>,
}

/// ANS1 Sequence.
#[napi(object, js_name = "ASN1Sequence")]
pub struct ASN1Sequence {
    pub r#type: &'static str,
}

/// HashMap for names to OID
static NAME_TO_OID_MAP: phf::Map<&'static str, &'static [u32]> = phf_map! {
    "sha256" => &[2, 16, 840, 1, 101, 3, 4, 2, 1],
    "sha3-256" => &[2, 16, 840, 1, 101, 3, 4, 2, 8],
    "sha3-256WithEcDSA" => &[2, 16, 840, 1, 101, 3, 4, 3, 10],
    "sha256WithEcDSA" => &[1, 2, 840, 10045, 4, 3, 2],
    "sha3-256WithEd25519" => &[],
    "ecdsa" => &[1, 2, 840, 10045, 2, 1],
    "ed25519" => &[1, 3, 101, 112],
    "secp256k1" => &[1, 3, 132, 0, 10],
    "account" => &[2, 23, 42, 2, 7, 11],
    "serialNumber" => &[2, 5, 4, 5],
    "member" => &[2, 5, 4, 31],
    "commonName" => &[2, 5, 4, 3],
    "hash" => &[1, 3, 6, 1, 4, 1, 8301, 3, 2, 2, 1, 1],
    "hashData" => &[2, 16, 840, 1, 101, 3, 3, 1, 3],
};

/// HashMap for an OID string to name
static OID_TO_NAME_MAP: phf::Map<&'static str, &'static str> = phf_map! {
    "2.16.840.1.101.3.4.2.1" => "sha256",
    "2.16.840.1.101.3.4.2.8" => "sha3-256",
    "2.16.840.1.101.3.4.3.10" => "sha3-256WithEcDSA",
    "1.2.840.10045.4.3.2" => "sha256WithEcDSA",
    "" => "sha3-256WithEd25519",
    "1.2.840.10045.2.1" => "ecdsa",
    "1.3.101.112" => "ed25519",
    "1.3.132.0.10" => "secp256k1",
    "2.23.42.2.7.11" => "account",
    "2.5.4.5" => "serialNumber",
    "2.5.4.31" => "member",
    "2.5.4.3" => "commonName",
    "1.3.6.1.4.1.8301.3.2.2.1.1" => "hash",
    "2.16.840.1.101.3.3.1.3" => "hashData",
};

fn get_oid_from_name<'a>(name: &'a str) -> Result<&'static [u32]> {
    if let Some(oid) = NAME_TO_OID_MAP.get(name) {
        Ok(*oid)
    } else {
        bail!(ASN1NAPIError::UnknownOid)
    }
}

fn get_name_from_oid(oid: &Oid) -> Result<&str> {
    if let Some(name) = OID_TO_NAME_MAP.get(&get_oid_string_from_oid(oid)) {
        Ok(*name)
    } else {
        bail!(ASN1NAPIError::UnknownOid)
    }
}

fn get_oid_string_from_oid(oid: &Oid) -> String {
    oid.iter()
        .map(|&e| e.to_string())
        .collect::<Vec<String>>()
        .join(".")
}

fn get_words_from_big_int(data: BigInt) -> (bool, Vec<u64>) {
    let (sign, words) = data.to_u64_digits();
    (sign == Sign::Minus, words)
}

/// Helper for handling date/times with milliseconds
fn get_utc_date_time_from_asn1_milli(data: &[u8]) -> Result<DateTime<Utc>> {
    let mut decoder: rasn::ber::de::Decoder =
        rasn::ber::de::Decoder::new(data, rasn::ber::de::DecoderOptions::ber());

    if let Ok(decoded) = Utf8String::decode_with_tag(&mut decoder, Tag::GENERALIZED_TIME) {
        Ok(DateTime::<FixedOffset>::from_utc(
            NaiveDateTime::parse_from_str(&decoded, "%Y%m%d%H%M%S%.3fZ")?,
            FixedOffset::east(0),
        )
        .with_timezone(&Utc))
    } else {
        bail!(ASN1NAPIError::MalformedData)
    }
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

/// Get an ASN1 boolean from a JsUnknown.
fn get_boolean_from_js(data: JsUnknown) -> Result<bool> {
    Ok(JsBoolean::from_unknown(data)?.get_value()?)
}

/// Get a string from a JsUnknown.
fn get_string_from_js(data: JsUnknown) -> Result<String> {
    Ok(JsString::from_unknown(data)?.into_utf8()?.into_owned()?)
}

/// Get an i64 integer from a JsUnknown.
fn get_integer_from_js(data: JsUnknown) -> Result<i64> {
    Ok(JsNumber::from_unknown(data)?.get_int64()?)
}

/// Get an i128 integer from a JsUnknown.
fn get_big_integer_from_js(data: JsUnknown) -> Result<BigInt> {
    Ok(BigInt::from_str(
        data.coerce_to_string()?.into_utf8()?.as_str()?,
    )?)
}

/// Get a Vec<u8> via a JsBuffer from a JsUnknown.
fn get_buffer_from_js(data: JsUnknown) -> Result<Vec<u8>> {
    Ok(JsBuffer::from_unknown(data)?.into_value()?.to_vec())
}

/// Get a Vec<u8> from a JsUnknown.
fn get_vec_from_js(data: JsUnknown) -> Result<Vec<u8>> {
    Ok(Vec::<u8>::from_unknown(data)?)
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

/// Get an chrono datetime from a JsUnknown.
/// JavaScript Date objects are described in
/// [Section 20.3](https://tc39.github.io/ecma262/#sec-date-objects)
/// of the ECMAScript Language Specification.
fn get_fixed_date_time_from_js(data: JsUnknown) -> Result<DateTime<FixedOffset>> {
    let js_date = JsDate::try_from(data)?;
    let timestamp = js_date.value_of()? as i64;
    let naive = NaiveDateTime::from_timestamp(timestamp / 1000, (timestamp % 1000) as u32);

    Ok(DateTime::<FixedOffset>::from_utc(
        naive,
        FixedOffset::east(0),
    ))
}

/// Return a JsType from a BER tag.
fn asn1_tag_to_js_tag(tag: Tag) -> JsType {
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
        Tag::BIT_STRING => JsType::BitString,
        Tag::OCTET_STRING => JsType::Buffer,
        Tag::SEQUENCE => JsType::Sequence,
        Tag::GENERALIZED_TIME => JsType::DateTime,
        Tag::UTC_TIME => JsType::DateTime,
        Tag::OBJECT_IDENTIFIER => JsType::Object,
        Tag::SET => JsType::Object,
        _ => JsType::Unknown,
    }
}

impl AsnType for ASN1Set {
    const TAG: Tag = Tag::SET;
}

impl AsnType for ASN1OID {
    const TAG: Tag = Tag::OBJECT_IDENTIFIER;
}

impl AsnType for ASN1BitString {
    const TAG: Tag = Tag::BIT_STRING;
}

impl AsnType for ASN1ContextTag {
    const TAG: Tag = Tag::SET;
}

impl AsnType for ASN1Data {
    const TAG: Tag = Tag::SET;
}

impl AsnType for ASN1Object {
    const TAG: Tag = Tag::SET;
}

impl Encode for ASN1BitString {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: Tag) -> Result<(), E::Error> {
        if let Ok(result) = BitString::try_from(self.value.clone()) {
            encoder.encode_bit_string(tag, &result)?;
            Ok(())
        } else {
            Err(<E as Encoder>::Error::custom(ASN1NAPIError::UnknownOid))
        }
    }
}

impl Decode for ASN1BitString {
    fn decode_with_tag<D: Decoder>(decoder: &mut D, tag: Tag) -> Result<Self, D::Error> {
        if let Ok(result) = decoder.decode_bit_string(tag) {
            Ok(ASN1BitString::from(result))
        } else {
            Err(<D as rasn::Decoder>::Error::custom(
                ASN1NAPIError::InvalidBitString,
            ))
        }
    }
}

impl Encode for ASN1OID {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: Tag) -> Result<(), E::Error> {
        if let Ok(result) = get_oid_from_name(&self.oid) {
            encoder.encode_object_identifier(tag, result)?;
            Ok(())
        } else {
            Err(<E as Encoder>::Error::custom(ASN1NAPIError::UnknownOid))
        }
    }
}

impl Decode for ASN1OID {
    fn decode_with_tag<D: Decoder>(decoder: &mut D, tag: Tag) -> Result<Self, D::Error> {
        if let Ok(result) = ASN1OID::try_from(decoder.decode_object_identifier(tag)?.to_vec()) {
            Ok(result)
        } else {
            Err(<D as rasn::Decoder>::Error::custom(
                ASN1NAPIError::UnknownOid,
            ))
        }
    }
}

impl Encode for ASN1Set {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: Tag) -> Result<(), E::Error> {
        encoder.encode_set(tag, |encoder| {
            encoder.encode_sequence(Tag::SEQUENCE, |encoder| {
                self.name.encode(encoder)?;
                self.value.encode_with_tag(encoder, Tag::PRINTABLE_STRING)?;
                Ok(())
            })?;

            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for ASN1Set {
    fn decode_with_tag<D: Decoder>(decoder: &mut D, _: Tag) -> Result<Self, D::Error> {
        decoder.decode_sequence(Tag::SET, |decoder| {
            decoder.decode_sequence(Tag::SEQUENCE, |decoder| {
                let name = ObjectIdentifier::decode(decoder)?;
                let value = PrintableString::decode(decoder)?;

                if let Ok(oid) = ASN1OID::try_from(name.to_vec()) {
                    Ok(Self {
                        r#type: ASN1ObjectType::Set.into(),
                        name: oid,
                        value: value.to_string(),
                    })
                } else {
                    Err(<D as Decoder>::Error::custom(ASN1NAPIError::UnknownOid))
                }
            })
        })
    }
}

// TODO Figure out a better way to handle this
impl Decode for ASN1Object {
    fn decode_with_tag<D: Decoder>(decoder: &mut D, _: Tag) -> Result<Self, D::Error> {
        if let Ok(obj) = ASN1Set::decode(decoder) {
            Ok(ASN1Object::ASN1Set(obj))
        } else if let Ok(obj) = ASN1OID::decode(decoder) {
            Ok(ASN1Object::ASN1OID(obj))
        } else if let Ok(obj) = ASN1BitString::decode(decoder) {
            Ok(ASN1Object::ASN1BitString(obj))
        } else {
            Err(<D as Decoder>::Error::custom(ASN1NAPIError::UnknownObject))
        }
    }
}

impl Encode for ASN1ContextTag {
    fn encode_with_tag<E: Encoder>(&self, _encoder: &mut E, _tag: Tag) -> Result<(), E::Error> {
        todo!()
    }
}

impl Decode for ASN1ContextTag {
    fn decode_with_tag<D: Decoder>(_decoder: &mut D, _tag: Tag) -> Result<Self, D::Error> {
        todo!()
    }
}

impl Encode for ASN1Data {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, _: Tag) -> Result<(), E::Error> {
        match self {
            ASN1Data::Bool(val) => {
                encoder.encode_bool(Tag::BOOL, *val)?;
                Ok(())
            }
            ASN1Data::BigInt(val) => {
                encoder.encode_integer(Tag::INTEGER, val)?;
                Ok(())
            }
            ASN1Data::Int(val) => {
                encoder.encode_integer(Tag::INTEGER, &BigInt::from(*val))?;
                Ok(())
            }
            ASN1Data::String(val) => {
                encoder.encode_utf8_string(Tag::PRINTABLE_STRING, val)?;
                Ok(())
            }
            ASN1Data::Bytes(val) => {
                encoder.encode_octet_string(Tag::OCTET_STRING, val)?;
                Ok(())
            }
            ASN1Data::Date(val) => {
                encoder.encode_generalized_time(Tag::GENERALIZED_TIME, val)?;
                Ok(())
            }
            ASN1Data::Object(obj) => match obj {
                ASN1Object::ASN1OID(oid) => oid.encode(encoder),
                ASN1Object::ASN1BitString(bstring) => bstring.encode(encoder),
                ASN1Object::ASN1Set(set) => set.encode(encoder),
                ASN1Object::ASN1ContextTag(context) => context.encode(encoder),
            },
            ASN1Data::Array(arr) => arr.encode(encoder),
            ASN1Data::Unknown => Err(<E as Encoder>::Error::custom(
                ASN1NAPIError::UnknownArgument,
            )),
        }
    }
}

impl ToString for ASN1ObjectType {
    /// Return the String representation of an ASN1Object Types.
    fn to_string(&self) -> String {
        match *self {
            ASN1ObjectType::BitString => ASN1_OBJECT_TYPE_BITSTRING.into(),
            ASN1ObjectType::Oid => ASN1_OBJECT_TYPE_OID.into(),
            ASN1ObjectType::Set => ASN1_OBJECT_TYPE_SET.into(),
            ASN1ObjectType::Context => ASN1_OBJECT_TYPE_CONTEXT.into(),
            _ => ASN1_OBJECT_TYPE_UNKNOWN.into(),
        }
    }
}

#[napi]
impl ASN1 {
    /// Create a new ANS1toJS instance from ASN1 encoded data.
    #[napi(constructor)]
    pub fn new(data: Vec<u8>) -> Result<Self> {
        // Match constructed Sequence/Set tag
        let bit = match *data.first().unwrap_or(&0x5) as u32 {
            0x30 => 0x10,
            0x31 => 0x11,
            n => n,
        } as u32;

        Ok(ASN1 {
            js_type: asn1_tag_to_js_tag(Tag::new(Class::Universal, bit)),
            data,
        })
    }

    /// Get the JsType of the encoded data.
    pub fn get_js_type(&self) -> &JsType {
        &self.js_type
    }

    /// Create an instance of ANS1 from a buffer.
    #[napi]
    pub fn from_buffer(value: Buffer) -> Result<Self> {
        Self::try_from(Vec::<u8>::from(value))
    }

    /// Create an instance of ANS1 from Base64 encoded data.
    #[napi]
    pub fn from_base64(value: String) -> Result<Self> {
        Self::try_from(value)
    }

    /// Create an instance of ANS1 from hex encoded data
    #[napi]
    pub fn from_hex(value: String) -> Result<Self> {
        if let Ok(result) = hex::decode(value) {
            Self::try_from(result.as_slice())
        } else {
            bail!(ASN1NAPIError::UnknownStringFormat)
        }
    }

    /// Decode ASN1 encoded data.
    pub fn decode<T: Decode>(&self) -> Result<T> {
        if let Ok(data) = decode::<T>(&self.data) {
            Ok(data)
        } else {
            bail!(ASN1NAPIError::MalformedData)
        }
    }

    /// Decode an object to an ASN1Object.
    pub fn into_object(&self) -> Result<ASN1Object> {
        self.decode::<ASN1Object>()
    }

    /// Convert to a big integer.
    pub fn into_big_integer(&self) -> Result<BigInt> {
        self.decode::<BigInt>()
    }

    /// Convert to an integer.
    #[napi]
    pub fn into_integer(&self) -> Result<i64> {
        self.decode::<i64>()
    }

    /// Convert to a JS big integer.
    #[napi]
    pub fn into_big_int(&self, env: Env) -> Result<JsBigInt> {
        let (bit, words) = get_words_from_big_int(self.decode::<BigInt>()?);
        Ok(env.create_bigint_from_words(bit, words)?)
    }

    /// Convert to a boolean.
    #[napi]
    pub fn into_bool(&self) -> Result<bool> {
        self.decode::<bool>()
    }

    /// Convert to a string.
    #[napi]
    pub fn into_string(&self) -> Result<String> {
        Ok(self.decode::<PrintableString>()?.as_str().into())
    }

    /// Convert to a date.
    #[napi]
    pub fn into_date(&self) -> Result<DateTime<Utc>> {
        if let Ok(date) = self.decode::<DateTime<FixedOffset>>() {
            Ok(date.with_timezone(&Utc))
        } else {
            get_utc_date_time_from_asn1_milli(&self.data)
        }
    }

    /// Convert to an byte array.
    #[napi]
    pub fn into_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.decode::<OctetString>()?.to_vec())
    }

    /// Convert to a buffer.
    #[napi]
    pub fn into_buffer(&self) -> Result<Buffer> {
        Ok(self.into_bytes()?.into())
    }

    /// Convert to an OID object.
    #[napi]
    pub fn into_oid(&self) -> Result<ASN1OID> {
        self.decode::<ASN1OID>()
    }

    /// Convert to a ASN1BitString object.
    #[napi]
    pub fn into_bitstring(&self) -> Result<ASN1BitString> {
        self.decode::<ASN1BitString>()
    }

    /// Convert to an Set object.
    #[napi]
    pub fn into_set(&self) -> Result<ASN1Set> {
        self.decode::<ASN1Set>()
    }

    /// Convert to an Context Tag object.
    #[napi]
    pub fn into_context_tag(&self) -> Result<ASN1ContextTag> {
        self.decode::<ASN1ContextTag>()
    }

    /// Convert a Sequence to an Array.
    #[napi]
    pub fn into_array(&self, env: Env) -> Result<Array> {
        let sequence = self.into_sequence()?;
        let mut array = env.create_array(sequence.len() as u32)?;

        for (i, data) in sequence.into_iter().enumerate() {
            array.set(i as u32, asn1_to_js_unknown(env, data)?)?;
        }

        Ok(array)
    }

    /// Convert to a decoded Sequence.
    #[napi]
    pub fn into_sequence(&self) -> Result<Vec<ASN1>> {
        if let Ok(sequence) = decode::<SequenceOf<Any>>(&self.data) {
            let mut result: Vec<ASN1> = Vec::new();

            for ber in sequence {
                result.push(ASN1::try_from(ber.as_bytes())?);
            }

            Ok(result)
        } else {
            bail!(ASN1NAPIError::MalformedData)
        }
    }
}

#[napi]
impl ASN1ContextTag {
    #[napi(getter)]
    pub fn contains(&self) -> Result<u32> {
        todo!()
    }
}

impl From<ASN1ObjectType> for &str {
    fn from(obj: ASN1ObjectType) -> Self {
        match obj {
            ASN1ObjectType::BitString => ASN1_OBJECT_TYPE_BITSTRING,
            ASN1ObjectType::Oid => ASN1_OBJECT_TYPE_OID,
            ASN1ObjectType::Set => ASN1_OBJECT_TYPE_SET,
            ASN1ObjectType::Context => ASN1_OBJECT_TYPE_CONTEXT,
            _ => ASN1_OBJECT_TYPE_UNKNOWN,
        }
    }
}

impl From<&str> for ASN1ObjectType {
    fn from(value: &str) -> Self {
        match value {
            ASN1_OBJECT_TYPE_BITSTRING => ASN1ObjectType::BitString,
            ASN1_OBJECT_TYPE_OID => ASN1ObjectType::Oid,
            ASN1_OBJECT_TYPE_SET => ASN1ObjectType::Set,
            ASN1_OBJECT_TYPE_CONTEXT => ASN1ObjectType::Context,
            _ => ASN1ObjectType::Unknown,
        }
    }
}

impl<'a> From<&'a [u8]> for ASN1BitString {
    fn from(value: &'a [u8]) -> Self {
        Self {
            r#type: ASN1ObjectType::BitString.into(),
            value: value.into(),
        }
    }
}

impl From<Vec<u8>> for ASN1BitString {
    fn from(value: Vec<u8>) -> Self {
        Self {
            r#type: ASN1ObjectType::BitString.into(),
            value,
        }
    }
}

impl From<BitString> for ASN1BitString {
    fn from(value: BitString) -> Self {
        Self::from(value.into_vec())
    }
}

impl TryFrom<String> for ASN1 {
    type Error = Error;

    /// Create an instance of ANS1toJS from Base64 or hex encoded data.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl<'a> TryFrom<&'a str> for ASN1 {
    type Error = Error;

    /// Create an instance of ANS1toJS from Base64 or hex encoded data.
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        if let Ok(result) = base64::decode(value) {
            Self::try_from(result.as_slice())
        } else if let Ok(result) = hex::decode(value) {
            Self::try_from(result.as_slice())
        } else {
            bail!(ASN1NAPIError::UnknownStringFormat)
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for ASN1 {
    type Error = Error;

    /// Create an instance of ANS1toJS from raw data.
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Self::new(value.into())
    }
}

impl TryFrom<Vec<u8>> for ASN1 {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl<'a> TryFrom<&'a [u8]> for ASN1OID {
    type Error = Error;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Self::try_from(value.iter().map(|&e| e as u32).collect::<Vec<u32>>())
    }
}

impl TryFrom<Vec<u32>> for ASN1OID {
    type Error = Error;

    fn try_from(value: Vec<u32>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl<'a> TryFrom<&'a [u32]> for ASN1OID {
    type Error = Error;

    fn try_from(value: &'a [u32]) -> Result<Self, Self::Error> {
        if let Some(oid) = Oid::new(value) {
            Ok(Self {
                r#type: ASN1ObjectType::Oid.into(),
                oid: get_name_from_oid(oid)?.into(),
            })
        } else {
            bail!(ASN1NAPIError::UnknownOid)
        }
    }
}

impl TryFrom<JsObject> for ASN1OID {
    type Error = Error;

    fn try_from(value: JsObject) -> Result<Self, Self::Error> {
        let oid = value.get_named_property::<JsString>(ASN1_OBJECT_TYPE_OID)?;
        let name = oid.into_utf8()?;

        Self::try_from(name.as_str()?)
    }
}

impl TryFrom<String> for ASN1OID {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl<'a> TryFrom<&'a str> for ASN1OID {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        if get_oid_from_name(value).is_ok() {
            Ok(Self {
                r#type: ASN1ObjectType::Oid.into(),
                oid: value.to_string(),
            })
        } else {
            bail!(ASN1NAPIError::UnknownOid)
        }
    }
}

impl TryFrom<JsObject> for ASN1BitString {
    type Error = Error;

    fn try_from(value: JsObject) -> Result<Self, Self::Error> {
        Self::try_from(value.get_named_property::<JsBuffer>(ASN1_OBJECT_VALUE_KEY)?)
    }
}

impl TryFrom<JsBuffer> for ASN1BitString {
    type Error = Error;

    fn try_from(value: JsBuffer) -> Result<Self, Self::Error> {
        Ok(Self {
            r#type: ASN1ObjectType::BitString.into(),
            value: value.into_value()?.to_vec(),
        })
    }
}

impl TryFrom<JsObject> for ASN1Set {
    type Error = Error;

    fn try_from(value: JsObject) -> Result<Self, Self::Error> {
        Ok(Self {
            r#type: ASN1ObjectType::Set.into(),
            name: ASN1OID::try_from(value.get_named_property::<JsObject>("name")?)?,
            value: value
                .get_named_property::<JsString>(ASN1_OBJECT_VALUE_KEY)?
                .into_utf8()?
                .as_str()?
                .into(),
        })
    }
}

impl TryFrom<JsObject> for ASN1ContextTag {
    type Error = Error;

    fn try_from(value: JsObject) -> Result<Self, Self::Error> {
        Ok(Self {
            r#type: ASN1ObjectType::Context.into(),
            value: get_integer_from_js(value.get_named_property::<JsUnknown>("name")?)?,
            data: get_buffer_from_js(value.get_named_property::<JsUnknown>("data")?)?,
        })
    }
}

impl TryFrom<ASN1> for ASN1Number {
    type Error = Error;

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

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use chrono::{TimeZone, Utc};
    use num_bigint::BigInt;

    //use crate::ASN1ContextTag;
    use crate::ASN1Set;
    use crate::JsType;
    use crate::ASN1;
    use crate::ASN1OID;
    use crate::ASN1_OBJECT_TYPE_OID;
    use crate::ASN1_OBJECT_TYPE_SET;

    // const TEST_VOTE: &str = "MFEGCWCGSAFlAwQCCDBEBCCb0PJlcOIUeBZH8vNeObY9pg\
    //                          xw+6PUh6ku6n9k9VVYDgQge0hOYtjbsjyJqqx5m7D8iP+i\
    //                          6dLBTcFsl/kwxUkaO1k=";
    const TEST_BLOCK: &str = "MIHWAgEAAgIByAIBexgTMjAyMjA2MjIxODE4MDAuMjEwW\
                              gQiAALE/SPerrujysUeJZetilu60VeOZ29M3vyUsjGPdq\
                              agsgQguP6a3fMrNmLVzXptmUh0I8Otu5S3fX4PWWBDbWx\
                              Ed+IwLDAqAgEABCIAA8GUaJ5YXCd7B46iRMLXMtmmPOW5\
                              v3MD2DK+so3K1BuRAgEKAkEA66ba0QK07zVrshYkOF3cO\
                              aW61T1ckn9QymeSBE+yE7EJPDnrN6g54KxBaAjRVFlT3i\
                              Ze4qTtQfXRoCkhoCgzqg==";

    #[test]
    fn test_asn1_into_bool() {
        let encoded_true = "AQH/";
        let encoded_false = "AQEA";

        let obj_true = ASN1::from_base64(encoded_true.into()).expect("base64");
        let obj_false = ASN1::from_base64(encoded_false.into()).expect("base64");

        assert!(obj_true.into_bool().unwrap());
        assert!(!obj_false.into_bool().unwrap());
    }

    #[test]
    fn test_asn_into_integer() {
        let encoded = "AgEq";
        let obj = ASN1::from_base64(encoded.into()).expect("base64");

        assert_eq!(obj.into_integer().unwrap(), 42_i64);

        let encoded = "AgP/AAE=";
        let obj = ASN1::from_base64(encoded.into()).expect("base64");

        assert_eq!(obj.into_integer().unwrap(), -65535_i64);
    }

    #[test]
    fn test_asn1_into_big_integer() {
        let encoded = "AgkBAgMEBQYHCAk=";
        let obj = ASN1::from_base64(encoded.into()).expect("base64");

        assert_eq!(
            obj.into_big_integer().unwrap(),
            BigInt::from(18591708106338011145_i128)
        );
    }

    #[test]
    fn test_asn1_into_string() {
        let encoded = "EwR0ZXN0";
        let obj = ASN1::from_base64(encoded.into()).expect("base64");

        assert_eq!(obj.into_string().unwrap(), "test");
    }

    #[test]
    fn test_asn1_into_date() {
        let encoded = "GA8yMDIyMDkyNjEwMDAwMFo=";
        let obj = ASN1::from_base64(encoded.into()).expect("base64");

        assert_eq!(
            obj.into_date().unwrap(),
            Utc.ymd(2022, 9, 26).and_hms_milli(10, 0, 0, 0)
        );
    }

    #[test]
    fn test_asn1_into_bytes() {
        let encoded = "BAUBAgMEBQ==";
        let obj = ASN1::from_base64(encoded.into()).expect("base64");

        assert_eq!(
            obj.into_bytes().unwrap(),
            vec![0x01, 0x02, 0x03, 0x04, 0x05]
        );
    }

    #[test]
    fn test_asn1_into_oid() {
        let encoded = "BglghkgBZQMEAgE=";
        let obj = ASN1::from_base64(encoded.into()).expect("base64");

        assert_eq!(
            obj.into_oid().unwrap(),
            ASN1OID {
                r#type: ASN1_OBJECT_TYPE_OID,
                oid: "sha256".into()
            }
        );
    }

    #[test]
    fn test_asn1_into_set() {
        let encoded = "MQ0wCwYDVQQDEwR0ZXN0";
        let obj = ASN1::from_base64(encoded.into()).expect("base64");

        assert_eq!(
            obj.into_set().unwrap(),
            ASN1Set {
                r#type: ASN1_OBJECT_TYPE_SET,
                name: ASN1OID {
                    r#type: ASN1_OBJECT_TYPE_OID,
                    oid: "commonName".into()
                },
                value: "test".into()
            }
        );
    }

    #[test]
    fn test_asn1_into_object() {
        let encoded = "MQ0wCwYDVQQDEwR0ZXN0";
        let obj = ASN1::from_base64(encoded.into()).expect("base64");

        println!("{:?}", obj.into_object());

        assert_eq!(
            obj.into_set().unwrap(),
            ASN1Set {
                r#type: ASN1_OBJECT_TYPE_SET,
                name: ASN1OID {
                    r#type: ASN1_OBJECT_TYPE_OID,
                    oid: "commonName".into()
                },
                value: "test".into()
            }
        );
    }

    // TODO
    #[ignore]
    #[test]
    fn test_asn1_into_context_tag() {
        let encoded = base64::encode([
            0xa0, 0x53, 0x30, 0x51, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x08, 0x30, 0x44, 0x04, 0x20, 0x13, 0x05, 0x77, 0x0e, 0x24, 0x9b, 0xd2, 0xe5, 0xd1,
            0x1e, 0xdf, 0xdb, 0xf0, 0xdb, 0x3f, 0xe3, 0x14, 0xa6, 0x40, 0x9b, 0x83, 0x12, 0x7e,
            0xbf, 0x5b, 0x21, 0xab, 0x92, 0xe2, 0x66, 0xe2, 0x14, 0x04, 0x20, 0x8d, 0x6d, 0x98,
            0x2e, 0xd9, 0x8b, 0x9c, 0x7f, 0xda, 0x27, 0x8b, 0x9c, 0x94, 0xe3, 0xa2, 0xe3, 0x93,
            0x34, 0x89, 0x43, 0x91, 0xdc, 0x5c, 0x0a, 0x88, 0x7b, 0x76, 0x01, 0x75, 0xa1, 0x77,
            0x30,
        ]);
        let obj = ASN1::from_base64(encoded.into()).expect("base64");

        println!("{:?}", obj.into_context_tag().unwrap());
    }

    #[test]
    fn test_asn1_block_into_sequence() {
        let obj = ASN1::from_base64(TEST_BLOCK.into()).expect("base64");
        let sequence: Vec<ASN1> = obj.into_sequence().expect("");

        assert_eq!(obj.get_js_type(), &JsType::Sequence);
        assert_eq!(sequence[0].get_js_type(), &JsType::Integer);
        assert_eq!(sequence[0].into_integer().unwrap(), 0);
        assert_eq!(sequence[1].get_js_type(), &JsType::Integer);
        assert_eq!(sequence[1].into_integer().unwrap(), 456);
        assert_eq!(sequence[2].get_js_type(), &JsType::Integer);
        assert_eq!(sequence[2].into_integer().unwrap(), 123);
        assert_eq!(sequence[3].get_js_type(), &JsType::DateTime);
        assert_eq!(
            sequence[3].into_date().unwrap(),
            Utc.ymd(2022, 6, 22).and_hms_milli(18, 18, 0, 210)
        );
        assert_eq!(sequence[4].get_js_type(), &JsType::Buffer);
        assert_eq!(
            sequence[4].into_bytes().unwrap(),
            hex::decode("0002C4FD23DEAEBBA3CAC51E2597AD8A5BBAD1578E676F4CDEFC94B2318F76A6A0B2")
                .unwrap()
        );
        assert_eq!(sequence[5].get_js_type(), &JsType::Buffer);
        assert_eq!(
            sequence[5].into_bytes().unwrap(),
            hex::decode("B8FE9ADDF32B3662D5CD7A6D99487423C3ADBB94B77D7E0F5960436D6C4477E2")
                .unwrap()
        );
        assert_eq!(sequence[6].get_js_type(), &JsType::Sequence);

        let nested_sequence: Vec<ASN1> = sequence[6].into_sequence().expect("");

        assert_eq!(nested_sequence[0].get_js_type(), &JsType::Sequence);

        let nested_sequence: Vec<ASN1> = nested_sequence[0].into_sequence().expect("");

        assert_eq!(nested_sequence[0].get_js_type(), &JsType::Integer);
        assert_eq!(nested_sequence[0].into_integer().unwrap(), 0);
        assert_eq!(nested_sequence[1].get_js_type(), &JsType::Buffer);
        assert_eq!(
            nested_sequence[1].into_bytes().unwrap(),
            hex::decode("0003C194689E585C277B078EA244C2D732D9A63CE5B9BF7303D832BEB28DCAD41B91")
                .unwrap()
        );
        assert_eq!(nested_sequence[2].get_js_type(), &JsType::Integer);
        assert_eq!(nested_sequence[2].into_integer().unwrap(), 10);

        assert_eq!(sequence[7].get_js_type(), &JsType::Integer);
        assert_eq!(
            sequence[7].into_big_integer().unwrap(),
            BigInt::from_str("12342084984267966262840258399369837191947502386530640049419263801438878759232954781610995155808851108259294273199446278227692318752971658125549615746397098")
                .unwrap()
        );
    }
}

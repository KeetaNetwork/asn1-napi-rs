#[macro_use]
extern crate napi_derive;

#[macro_use]
extern crate phf;

use anyhow::{bail, Error, Result};
use chrono::{DateTime, FixedOffset, NaiveDateTime, TimeZone, Utc};
use der_parser::ber::{
    ber_read_element_header, parse_ber_bitstring, parse_ber_bmpstring, parse_ber_bool,
    parse_ber_generalizedtime, parse_ber_generalstring, parse_ber_graphicstring,
    parse_ber_ia5string, parse_ber_integer, parse_ber_null, parse_ber_numericstring,
    parse_ber_octetstring, parse_ber_oid, parse_ber_printablestring, parse_ber_sequence,
    parse_ber_set, parse_ber_t61string, parse_ber_universalstring, parse_ber_utctime,
    parse_ber_utf8string, parse_ber_videotexstring, parse_ber_visiblestring, BerObject,
    BerObjectContent, Tag,
};
use napi::{
    bindgen_prelude::{Buffer, FromNapiValue, ToNapiValue},
    Env, JsBigInt, JsBoolean, JsBuffer, JsDate, JsNumber, JsObject, JsString, JsUnknown, ValueType,
};
use rasn::{
    ber::decode,
    types::{BitString, ObjectIdentifier, OctetString, Oid},
};
use rasn::{ber::encode, types::PrintableString};
use thiserror::Error;

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
    // TODO
    // #[error("We only know how to handle sets with 1 sequence")]
    // InvalidSetLength,
    // #[error("Set->Sequence must contain 2 values")]
    // InvalidSetSequenceLength,
    // #[error("Set->Sequence must contain and OID and String")]
    // InvalidSetData,
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
    Sequence = 0x10,
    Set = 0x11,
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
#[napi]
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

pub enum ASN1Object {
    ASN1OID(ASN1OID),
    ASN1Set(ASN1Set),
    ASN1BitString(ASN1BitString),
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
    BigInt(i128),
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

/// ANS1 bitstring.
#[napi(object, js_name = "ASN1BitString")]
pub struct ASN1BitString {
    pub r#type: &'static str,
    pub value: Buffer,
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

fn get_oid_from_oid_string<'a>(oid: &'a str) -> Result<&'static [u32]> {
    get_oid_from_name(get_name_from_oid_string(oid)?)
}

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

fn get_name_from_oid_string(oid: &str) -> Result<&str> {
    if let Some(name) = OID_TO_NAME_MAP.get(oid) {
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
    Ok(match data.get_type()? {
        ValueType::Boolean => encode(&get_boolean_from_js(data)?).unwrap(),
        ValueType::BigInt => encode(&get_big_integer_from_js(data)?).unwrap(),
        ValueType::Number => encode(&get_integer_from_js(data)?).unwrap(),
        ValueType::String => encode(&PrintableString::from(get_string_from_js(data)?)).unwrap(),
        ValueType::Object if data.is_buffer()? => {
            encode(&OctetString::from(get_buffer_from_js(data)?)).unwrap()
        }
        ValueType::Object if data.is_date()? => {
            encode(&get_fixed_date_time_from_js(data)?).unwrap()
        }
        ValueType::Object => match get_object_from_js(data)? {
            ASN1Object::ASN1OID(oid) => {
                encode(&ObjectIdentifier::new(get_oid_from_name(&oid.oid)?).unwrap()).unwrap()
            }
            ASN1Object::ASN1BitString(bstring) => {
                let data: Vec<u8> = bstring.value.into();
                encode(&BitString::try_from(data).unwrap()).unwrap()
            }
            _ => todo!(),
        },
        ValueType::Unknown if data.is_array()? => {
            println!("{:?}", data.get_type());
            // let obj: Vec<JsUnknown> = data.coerce_to_object()?.to_vec();
            // writer = Sequence::from_iter_to_der(obj).unwrap();
            todo!()
        }
        _ => {
            bail!(ASN1NAPIError::UnknownArgument)
        }
    })
}

/// Convert ASN1 BER encoded data to JS native types.
#[napi(strict, js_name = "ASN1toJS")]
pub fn asn1_to_js(env: Env, data: JsUnknown) -> Result<JsUnknown> {
    let asn1 = match data.get_type()? {
        ValueType::String => ASN1::try_from(data.coerce_to_string()?.into_utf8()?.as_str()?)?,
        ValueType::Object if data.is_array()? => ASN1::new(get_array_from_js(data)?)?,
        ValueType::Object if data.is_buffer()? => ASN1::new(get_buffer_from_js(data)?)?,
        _ => bail!(ASN1NAPIError::UnknownArgument),
    };

    Ok(match asn1.get_type() {
        JsType::Integer => match ASN1Number::try_from(asn1)? {
            ASN1Number::Integer(val) => env.create_int64(val)?.into_unknown(),
            ASN1Number::BigInt(val) => env.create_bigint_from_i128(val)?.into_unknown()?,
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
        JsType::Object => todo!(),
        JsType::Sequence => todo!(),
        _ => env.get_null()?.into_unknown(),
    })
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
fn get_big_integer_from_js(data: JsUnknown) -> Result<i128> {
    Ok(JsBigInt::from_unknown(data)?.get_i128()?.0)
}

/// Get a Vec<u8> via a JsBuffer from a JsUnknown.
fn get_buffer_from_js(data: JsUnknown) -> Result<Vec<u8>> {
    Ok(JsBuffer::from_unknown(data)?.into_value()?.to_vec())
}

/// Get a Vec<u8> via a JsArrayBuffer from a JsUnknown.
// fn get_array_buffer_from_js(data: JsUnknown) -> Result<Vec<u8>> {
//     Ok(JsArrayBuffer::from_unknown(data)?.into_value()?.to_vec())
// }

/// Get a Vec<u8> from a JsUnknown.
fn get_array_from_js(data: JsUnknown) -> Result<Vec<u8>> {
    Ok(Vec::<u8>::from_unknown(data)?)
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

/// Convert raw data from BER encoding
fn get_ber_object(data: &'_ [u8]) -> Result<BerObject<'_>> {
    let (_, header) = ber_read_element_header(data)?;
    let (_, result) = match header.tag() {
        Tag::Null => parse_ber_null(&[]),
        Tag::Utf8String => parse_ber_utf8string(data),
        Tag::PrintableString => parse_ber_printablestring(data),
        Tag::BitString => parse_ber_bitstring(data),
        Tag::VisibleString => parse_ber_visiblestring(data),
        Tag::UniversalString => parse_ber_universalstring(data),
        Tag::GeneralString => parse_ber_generalstring(data),
        Tag::OctetString => parse_ber_octetstring(data),
        Tag::BmpString => parse_ber_bmpstring(data),
        Tag::GraphicString => parse_ber_graphicstring(data),
        Tag::Ia5String => parse_ber_ia5string(data),
        Tag::VideotexString => parse_ber_videotexstring(data),
        Tag::TeletexString => parse_ber_t61string(data),
        Tag::NumericString => parse_ber_numericstring(data),
        Tag::Integer => parse_ber_integer(data),
        Tag::Boolean => parse_ber_bool(data),
        Tag::Sequence => parse_ber_sequence(data),
        Tag::GeneralizedTime => parse_ber_generalizedtime(data),
        Tag::UtcTime => parse_ber_utctime(data),
        Tag::Oid => parse_ber_oid(data),
        Tag::Set => parse_ber_set(data),
        tag => {
            println!("{:?}", tag);
            todo!()
        }
    }?;

    Ok(result)
}

/// Get a chrono DateTime from a BerObject
fn get_chrono_from_ber_object(obj: BerObject) -> Result<DateTime<Utc>> {
    if let BerObjectContent::GeneralizedTime(data) = obj.content {
        Ok(Utc
            .ymd(
                data.year.try_into()?,
                data.month.try_into()?,
                data.day.try_into()?,
            )
            .and_hms(
                data.hour.try_into()?,
                data.minute.try_into()?,
                data.second.try_into()?,
            ))
    } else {
        bail!(ASN1NAPIError::UnknownArgument)
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
        let (_, header) = ber_read_element_header(&data)?;

        Ok(ASN1 {
            js_type: Self::fetch_type(header.tag()),
            data,
        })
    }

    /// Return a JsType from a BER tag.
    pub fn fetch_type(tag: Tag) -> JsType {
        match tag {
            Tag::Boolean => JsType::Boolean,
            Tag::Integer => JsType::Integer,
            Tag::Null => JsType::Null,
            Tag::Utf8String => JsType::String,
            Tag::PrintableString => JsType::String,
            Tag::VisibleString => JsType::String,
            Tag::UniversalString => JsType::String,
            Tag::GeneralString => JsType::String,
            Tag::GraphicString => JsType::String,
            Tag::Ia5String => JsType::String,
            Tag::VideotexString => JsType::String,
            Tag::TeletexString => JsType::String,
            Tag::NumericString => JsType::String,
            Tag::BmpString => JsType::String,
            Tag::BitString => JsType::BitString,
            Tag::OctetString => JsType::Buffer,
            Tag::Sequence => JsType::Sequence,
            Tag::GeneralizedTime => JsType::DateTime,
            Tag::UtcTime => JsType::DateTime,
            Tag::Oid => JsType::Object,
            Tag::Set => JsType::Object,
            _ => JsType::Unknown,
        }
    }

    /// Get the JsType of the encoded data.
    #[napi(getter)]
    pub fn get_type(&self) -> JsType {
        self.js_type
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

    /// Convert to an integer.
    #[napi]
    pub fn into_integer(&self) -> Result<i64> {
        if let Ok(data) = decode::<i64>(&self.data) {
            Ok(data)
        } else {
            bail!(ASN1NAPIError::MalformedData)
        }
    }

    /// Convert to a big integer.
    #[napi]
    pub fn into_big_integer(&self) -> Result<i128> {
        if let Ok(data) = decode::<i128>(&self.data) {
            Ok(data)
        } else {
            bail!(ASN1NAPIError::MalformedData)
        }
    }

    /// Convert to a boolean.
    #[napi]
    pub fn into_bool(&self) -> Result<bool> {
        if let Ok(data) = decode::<bool>(&self.data) {
            Ok(data)
        } else {
            bail!(ASN1NAPIError::MalformedData)
        }
    }

    /// Convert to a string.
    #[napi]
    pub fn into_string(&self) -> Result<String> {
        if let Ok(data) = get_ber_object(&self.data) {
            Ok(data.as_str()?.to_string())
        } else {
            bail!(ASN1NAPIError::MalformedData)
        }
    }

    /// Convert to a date.
    #[napi]
    pub fn into_date(&self) -> Result<DateTime<Utc>> {
        if let Ok(data) = get_ber_object(&self.data) {
            Ok(get_chrono_from_ber_object(data)?)
        } else {
            bail!(ASN1NAPIError::MalformedData)
        }
    }

    /// Convert to an array.
    #[napi]
    pub fn into_array(&self) -> Result<&[u8]> {
        if let Ok(data) = get_ber_object(&self.data) {
            Ok(data.as_slice()?)
        } else {
            bail!(ASN1NAPIError::MalformedData)
        }
    }

    /// Convert to a buffer.
    #[napi]
    pub fn into_buffer(&self) -> Result<Buffer> {
        if let Ok(data) = get_ber_object(&self.data) {
            Ok(data.as_slice()?.into())
        } else {
            bail!(ASN1NAPIError::MalformedData)
        }
    }

    /// Convert to an OID object.
    #[napi]
    pub fn into_oid(&self) -> Result<ASN1OID> {
        if let Ok(data) = get_ber_object(&self.data) {
            let oid = &data.as_oid()?.to_id_string();
            ASN1OID::try_from(get_oid_from_oid_string(oid)?)
        } else {
            bail!(ASN1NAPIError::MalformedData)
        }
    }

    /// Convert to a ASN1BitString object.
    #[napi]
    pub fn into_bitstring(&self) -> Result<ASN1BitString> {
        if let Ok(data) = get_ber_object(&self.data) {
            Ok(ASN1BitString::from(data.as_bitstring()?.data))
        } else {
            bail!(ASN1NAPIError::MalformedData)
        }
    }

    /// Convert to an Set object.
    #[napi]
    pub fn into_set(&self) -> Result<ASN1Set> {
        if let Ok(data) = get_ber_object(&self.data) {
            ASN1Set::try_from(data.as_set()?)
        } else {
            bail!(ASN1NAPIError::MalformedData)
        }
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

    /// Create an instance of ANS1toJS from Base64 encoded data.
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if let Ok(data) = get_ber_object(value)?.to_vec() {
            Self::new(data)
        } else {
            bail!(ASN1NAPIError::UnknownArgument)
        }
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
        Self::try_from(value.get_named_property::<JsBuffer>("value")?)
    }
}

impl TryFrom<JsBuffer> for ASN1BitString {
    type Error = Error;

    fn try_from(value: JsBuffer) -> Result<Self, Self::Error> {
        Ok(Self {
            r#type: ASN1ObjectType::BitString.into(),
            value: value.into_value()?.to_vec().into(),
        })
    }
}

impl<'a> TryFrom<&Vec<BerObject<'a>>> for ASN1Set {
    type Error = Error;

    fn try_from(_: &Vec<BerObject<'a>>) -> Result<Self, Self::Error> {
        todo!()
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
    use chrono::{TimeZone, Utc};
    use der_parser::ber::{parse_ber_sequence, Tag};

    use crate::get_ber_object;
    use crate::ASN1;
    use crate::ASN1OID;
    use crate::ASN1_OBJECT_TYPE_OID;

    const TEST_BLOCK: &str = "MIHWAgEAAgIByAIBexgTMjAyMjA2MjIxODE4MDAuMjEwW\
                              gQiAALE/SPerrujysUeJZetilu60VeOZ29M3vyUsjGPdq\
                              agsgQguP6a3fMrNmLVzXptmUh0I8Otu5S3fX4PWWBDbWx\
                              Ed+IwLDAqAgEABCIAA8GUaJ5YXCd7B46iRMLXMtmmPOW5\
                              v3MD2DK+so3K1BuRAgEKAkEA66ba0QK07zVrshYkOF3cO\
                              aW61T1ckn9QymeSBE+yE7EJPDnrN6g54KxBaAjRVFlT3i\
                              Ze4qTtQfXRoCkhoCgzqg==";

    #[test]
    fn test_lib_asn1_sequence() {
        let data = base64::decode(TEST_BLOCK).expect("base64");
        let (_, sequence) = parse_ber_sequence(&data).expect("Failed to parse object");

        sequence.ref_iter().for_each(|element| {
            println!("{:?}", element);
        });

        assert_eq!(sequence.header.tag(), Tag::Sequence);
    }

    #[test]
    fn test_asn1_get_ber_object() {
        let bytes = vec![0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x03, 0x01, 0x00, 0x00];
        let convert = get_ber_object(&bytes);

        assert!(convert.is_ok());
        assert_eq!(convert.unwrap().content.as_u64(), Ok(65537));
    }

    #[test]
    fn test_asn1_to_js_into_bool() {
        let encoded_true = "AQH/";
        let encoded_false = "AQEA";

        let obj_true = ASN1::from_base64(encoded_true.into()).expect("base64");
        let obj_false = ASN1::from_base64(encoded_false.into()).expect("base64");

        assert!(obj_true.into_bool().unwrap());
        assert!(!obj_false.into_bool().unwrap());
    }

    #[test]
    fn test_asn1_to_js_into_integer() {
        let encoded = "AgEq";
        let obj = ASN1::from_base64(encoded.into()).expect("base64");

        assert_eq!(obj.into_integer().unwrap(), 42_i64);

        let encoded = "AgP/AAE=";
        let obj = ASN1::from_base64(encoded.into()).expect("base64");

        assert_eq!(obj.into_integer().unwrap(), -65535_i64);
    }

    #[test]
    fn test_asn1_to_js_into_big_integer() {
        let encoded = "AgkBAgMEBQYHCAk=";
        let obj = ASN1::from_base64(encoded.into()).expect("base64");

        assert_eq!(obj.into_big_integer().unwrap(), 18591708106338011145);
    }

    #[test]
    fn test_asn1_to_js_into_string() {
        let encoded = "EwR0ZXN0";
        let obj = ASN1::from_base64(encoded.into()).expect("base64");

        assert_eq!(obj.into_string().unwrap(), "test");
    }

    #[test]
    fn test_asn1_to_js_into_date() {
        let encoded = "GA8yMDIyMDkyNjEwMDAwMFo=";
        let obj = ASN1::from_base64(encoded.into()).expect("base64");

        assert_eq!(
            obj.into_date().unwrap(),
            Utc.ymd(2022, 9, 26).and_hms_milli(10, 0, 0, 0)
        );
    }

    #[test]
    fn test_asn1_to_js_into_array() {
        let encoded = "BAUBAgMEBQ==";
        let obj = ASN1::from_base64(encoded.into()).expect("base64");

        assert_eq!(
            obj.into_array().unwrap(),
            vec![0x01, 0x02, 0x03, 0x04, 0x05]
        );
    }

    #[test]
    fn test_asn1_to_js_into_oid() {
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
}

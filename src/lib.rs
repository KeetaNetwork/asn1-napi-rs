#[macro_use]
extern crate napi_derive;

#[macro_use]
extern crate phf;

#[macro_use]
extern crate der_parser;

use std::borrow::Cow;

use anyhow::{bail, Error, Result};
use asn1_rs::{
    ASN1DateTime, Boolean, GeneralizedTime, Integer, OctetString, PrintableString, ToDer, UtcTime,
};
use chrono::{DateTime, Datelike, NaiveDateTime, TimeZone, Timelike, Utc};
use der_parser::ber::{
    ber_read_element_header, parse_ber_bitstring, parse_ber_bool, parse_ber_generalizedtime,
    parse_ber_generalstring, parse_ber_integer, parse_ber_null, parse_ber_octetstring,
    parse_ber_oid, parse_ber_printablestring, parse_ber_sequence, parse_ber_universalstring,
    parse_ber_utctime, parse_ber_utf8string, parse_ber_visiblestring, BerObject, BerObjectContent,
    Tag,
};
use der_parser::Oid;
use napi::{
    bindgen_prelude::{Buffer, FromNapiValue, ToNapiValue},
    JsBigInt, JsBoolean, JsBuffer, JsDate, JsNumber, JsObject, JsString, JsUnknown, ValueType,
};
use thiserror::Error;

/// Library errors
#[derive(Error, Debug)]
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
}

/// TODO Native encoding without ASN1 dependencies
pub enum UniversalTag {
    Boolean = 0x01, // +
    Integer = 0x02, // +
    BitString = 0x03,
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
    NumericString = 0x12,
    PrintableString = 0x13, // +
    TelexString = 0x14,
    VideotexString = 0x15,
    IA5String = 0x16,
    UTCTime = 0x17,         // +
    GeneralizedTime = 0x18, // +
    GraphicString = 0x19,
    VisibleString = 0x1A,   // +
    GeneralString = 0x1B,   // +
    UniversalString = 0x1C, // +
    ChracterString = 0x1D,
    BMPString = 0x1E,
}

unsafe impl Send for UniversalTag {}
unsafe impl Sync for UniversalTag {}

/// JavaScript Types
#[napi]
#[derive(Hash, Eq, PartialEq, Debug)]
pub enum JsType {
    Sequence,
    Integer,
    DateTime,
    Null,
    String,
    Boolean,
    Unknown,
    Undefined,
}

/// Convert ASN1 BER encoded data to JS native types.
#[napi(js_name = "Asn1")]
#[derive(Debug)]
pub struct ASN1toJS {
    js_type: JsType,
    data: Vec<u8>,
}

/// ANS1 OID.
#[napi(object, js_name = "ASN1OID")]
#[derive(Hash, Eq, PartialEq, Debug)]
pub struct ASN1OID {
    pub r#type: String,
    pub oid: String,
}

#[derive(Hash, Eq, PartialEq, Debug)]
pub enum ASN1Object {
    ASN1OID(ASN1OID),
}

/// HashMap for names to OID
static NAME_TO_OID_MAP: phf::Map<&'static str, Oid> = phf_map! {
    "sha256" => oid!(2.16.840.1.101.3.4.2.1),
    "sha3-256" => oid!(2.16.840.1.101.3.4.2.8),
    "sha3-256WithEcDSA" => oid!(2.16.840.1.101.3.4.3.10),
    "sha256WithEcDSA" => oid!(1.2.840.10045.4.3.2),
    "sha3-256WithEd25519" => Oid::new(Cow::Borrowed(&[])),
    "ecdsa" => oid!(1.2.840.10045.2.1),
    "ed25519" => oid!(1.3.101.112),
    "secp256k1" => oid!(1.3.132.0.10),
    "account" => oid!(2.23.42.2.7.11),
    "serialNumber" => oid!(2.5.4.5),
    "member" => oid!(2.5.4.31),
    "commonName" => oid!(2.5.4.3),
    "hash" => oid!(1.3.6.1.4.1.8301.3.2.2.1.1),
    "hashData" => oid!(2.16.840.1.101.3.3.1.3),
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

fn get_oid_from_name(name: &str) -> Option<&Oid> {
    NAME_TO_OID_MAP.get(name)
}

fn get_name_from_oid(oid: Oid) -> Option<&str> {
    if let Some(name) = OID_TO_NAME_MAP.get(&oid.to_string()) {
        Some(*name)
    } else {
        None
    }
}

/// Convert JS input into ASN1 BER encoded data.
///
/// See [`asn1_rs::asn1_types`]
#[napi(js_name = "JStoASN1")]
pub fn js_to_asn1(data: JsUnknown) -> Result<Vec<u8>> {
    let mut writer = Vec::new();

    match data.get_type()? {
        ValueType::Boolean => {
            Boolean::new(if get_boolean_from_js(data)? { 1 } else { 0 }).write_der(&mut writer)?
        }
        ValueType::BigInt => {
            Integer::from_i128(get_big_integer_from_js(data)?).write_der(&mut writer)?
        }
        ValueType::Number => {
            Integer::from_i32(get_integer_from_js(data)?).write_der(&mut writer)?
        }
        ValueType::String => {
            PrintableString::from(get_string_from_js(data)?).write_der(&mut writer)?
        }
        ValueType::Object if data.is_buffer()? => {
            OctetString::from(get_buffer_from_js(data)?.as_ref()).write_der(&mut writer)?
        }
        ValueType::Object if data.is_date()? => {
            chrono_to_generalized_time(get_date_time_from_js(data)?).write_der(&mut writer)?
        }
        ValueType::Object => match get_object_from_js(data)? {
            ASN1Object::ASN1OID(oid) => get_oid_from_name(&oid.oid)
                .unwrap()
                .write_der(&mut writer)?,
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
    };

    Ok(writer)
}

#[napi(js_name = "ASN1toJS")]
pub fn asn1_to_js(_data: JsUnknown) -> Result<JsUnknown> {
    todo!()
}

/// Get an ASN1 boolean from a JsUnknown.
fn get_boolean_from_js(data: JsUnknown) -> Result<bool> {
    Ok(JsBoolean::from_unknown(data)?.get_value()?)
}

/// Get a string from a JsUnknown.
fn get_string_from_js(data: JsUnknown) -> Result<String> {
    Ok(JsString::from_unknown(data)?.into_utf8()?.into_owned()?)
}

/// Get an i32 integer from a JsUnknown.
fn get_integer_from_js(data: JsUnknown) -> Result<i32> {
    Ok(JsNumber::from_unknown(data)?.get_int32()?)
}

/// Get an i128 integer from a JsUnknown.
fn get_big_integer_from_js(data: JsUnknown) -> Result<i128> {
    Ok(JsBigInt::from_unknown(data)?.get_i128()?.0)
}

/// Get a Vec<u8> via a JsBuffer from a JsUnknown.
fn get_buffer_from_js(data: JsUnknown) -> Result<Vec<u8>> {
    Ok(JsBuffer::from_unknown(data)?.into_value()?.to_vec())
}

/// Get an ASN1Object from a JsUnknown.
fn get_object_from_js(data: JsUnknown) -> Result<ASN1Object> {
    let obj = data.coerce_to_object()?;
    let field = obj.get_named_property::<JsUnknown>("type")?;

    if let Ok(ValueType::String) = field.get_type() {
        let name = get_string_from_js(field)?;

        Ok(match name.as_str() {
            "oid" => ASN1Object::ASN1OID(ASN1OID::try_from(obj)?),
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
fn get_date_time_from_js(data: JsUnknown) -> Result<DateTime<Utc>> {
    let js_date = JsDate::try_from(data)?;
    let timestamp = js_date.value_of()? as i64;
    let naive = NaiveDateTime::from_timestamp(timestamp / 1000, (timestamp % 1000) as u32);

    Ok(DateTime::from_utc(naive, Utc))
}

/// Convert a chrono time to a GeneralizedTime.
pub fn chrono_to_generalized_time<T: TimeZone>(date: DateTime<T>) -> GeneralizedTime {
    GeneralizedTime::new(ASN1DateTime::new(
        date.year() as u32,
        date.month() as u8,
        date.day() as u8,
        date.hour() as u8,
        date.minute() as u8,
        date.second() as u8,
        Some(date.timestamp_subsec_millis() as u16),
        asn1_rs::ASN1TimeZone::Offset(0, 0),
    ))
}

/// Convert a chrono time to a UtcTime.
pub fn chrono_to_utc_time<T: TimeZone>(date: DateTime<T>) -> UtcTime {
    UtcTime::new(ASN1DateTime::new(
        date.year() as u32,
        date.month() as u8,
        date.day() as u8,
        date.hour() as u8,
        date.minute() as u8,
        date.second() as u8,
        Some(date.timestamp_subsec_millis() as u16),
        asn1_rs::ASN1TimeZone::Offset(0, 0),
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
        Tag::Integer => parse_ber_integer(data),
        Tag::Boolean => parse_ber_bool(data),
        Tag::Sequence => parse_ber_sequence(data),
        Tag::GeneralizedTime => parse_ber_generalizedtime(data),
        Tag::UtcTime => parse_ber_utctime(data),
        Tag::Oid => parse_ber_oid(data),
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

#[napi]
impl ASN1toJS {
    /// Create a new ANS1toJS instance from ASN1 encoded data.
    #[napi(constructor)]
    pub fn new(data: Vec<u8>) -> Result<Self> {
        let (_, header) = ber_read_element_header(&data)?;

        Ok(ASN1toJS {
            js_type: Self::fetch_type(header.tag()),
            data,
        })
    }

    /// Return a JsType from a BER tag.
    pub fn fetch_type(tag: Tag) -> JsType {
        match tag {
            Tag::Boolean => JsType::Boolean,
            Tag::Integer => JsType::Integer,
            _ => JsType::Unknown,
        }
    }

    /// Get the JsType of the encoded data.
    #[napi(getter)]
    pub fn get_type(&self) -> JsType {
        self.js_type
    }

    /// Create an instance of ANS1toJS from Base64 encoded data.
    #[napi]
    pub fn from_base64(value: String) -> Result<Self> {
        Self::try_from(value)
    }

    /// Create an instance of ANS1toJS from hex encoded data
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
    pub fn into_integer(&self) -> Result<i32> {
        if let Ok(data) = get_ber_object(&self.data) {
            Ok(data.as_i32()?)
        } else {
            bail!(ASN1NAPIError::MalformedData)
        }
    }

    /// Convert to a big integer.
    #[napi]
    pub fn into_big_integer(&self) -> Result<i128> {
        if let Ok(data) = get_ber_object(&self.data) {
            Ok(i128::try_from(data.as_bigint()?)?)
        } else {
            bail!(ASN1NAPIError::MalformedData)
        }
    }

    /// Convert to a boolean.
    #[napi]
    pub fn into_bool(&self) -> Result<bool> {
        if let Ok(data) = get_ber_object(&self.data) {
            Ok(data.as_bool()?)
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
            ASN1OID::try_from(data.as_oid()?.to_owned())
        } else {
            bail!(ASN1NAPIError::MalformedData)
        }
    }
}

impl TryFrom<String> for ASN1toJS {
    type Error = Error;

    /// Create an instance of ANS1toJS from Base64 or hex encoded data.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl<'a> TryFrom<&'a str> for ASN1toJS {
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

impl<'a> TryFrom<&'a [u8]> for ASN1toJS {
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

impl TryFrom<Oid<'_>> for ASN1OID {
    type Error = Error;

    fn try_from(value: Oid) -> Result<Self, Self::Error> {
        if let Some(name) = get_name_from_oid(value) {
            Ok(Self {
                r#type: "oid".to_string(),
                oid: name.to_string(),
            })
        } else {
            bail!(ASN1NAPIError::UnknownOid)
        }
    }
}

impl TryFrom<JsObject> for ASN1OID {
    type Error = Error;

    fn try_from(value: JsObject) -> Result<Self, Self::Error> {
        let oid = value.get_named_property::<JsString>("oid")?;
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
        if get_oid_from_name(value).is_some() {
            Ok(Self {
                r#type: "oid".to_string(),
                oid: value.to_string(),
            })
        } else {
            bail!(ASN1NAPIError::UnknownOid)
        }
    }
}

#[cfg(test)]
mod test {
    use chrono::{TimeZone, Utc};
    use der_parser::ber::{parse_ber_sequence, Tag};

    use crate::get_ber_object;
    use crate::ASN1toJS;
    use crate::ASN1OID;

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

        let obj_true = ASN1toJS::from_base64(encoded_true.into()).expect("base64");
        let obj_false = ASN1toJS::from_base64(encoded_false.into()).expect("base64");

        assert!(obj_true.into_bool().unwrap());
        assert!(!obj_false.into_bool().unwrap());
    }

    #[test]
    fn test_asn1_to_js_into_integer() {
        let encoded = "AgEq";
        let obj = ASN1toJS::from_base64(encoded.into()).expect("base64");

        assert_eq!(obj.into_integer().unwrap(), 42_i32);
    }

    #[test]
    fn test_asn1_to_js_into_big_integer() {
        let encoded = "AgkBAgMEBQYHCAk=";
        let obj = ASN1toJS::from_base64(encoded.into()).expect("base64");

        assert_eq!(obj.into_big_integer().unwrap(), 18591708106338011145);
    }

    #[test]
    fn test_asn1_to_js_into_string() {
        let encoded = "EwR0ZXN0";
        let obj = ASN1toJS::from_base64(encoded.into()).expect("base64");

        assert_eq!(obj.into_string().unwrap(), "test");
    }

    #[test]
    fn test_asn1_to_js_into_date() {
        let encoded = "GA8yMDIyMDkyNjEwMDAwMFo=";
        let obj = ASN1toJS::from_base64(encoded.into()).expect("base64");

        assert_eq!(
            obj.into_date().unwrap(),
            Utc.ymd(2022, 9, 26).and_hms_milli(10, 0, 0, 0)
        );
    }

    #[test]
    fn test_asn1_to_js_into_array() {
        let encoded = "BAUBAgMEBQ==";
        let obj = ASN1toJS::from_base64(encoded.into()).expect("base64");

        assert_eq!(
            obj.into_array().unwrap(),
            vec![0x01, 0x02, 0x03, 0x04, 0x05]
        );
    }

    #[test]
    fn test_asn1_to_js_into_oid() {
        let encoded = "BglghkgBZQMEAgE=";
        let obj = ASN1toJS::from_base64(encoded.into()).expect("base64");

        assert_eq!(
            obj.into_oid().unwrap(),
            ASN1OID {
                r#type: "oid".into(),
                oid: "sha256".into()
            }
        );
    }
}

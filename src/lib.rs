#![deny(clippy::all)]

#[macro_use]
extern crate napi_derive;

use asn1_rs::{Boolean, Integer, PrintableString, ToDer};
use der_parser::ber::{
    ber_read_element_header, parse_ber_bool, parse_ber_generalizedtime, parse_ber_integer,
    parse_ber_null, parse_ber_printablestring, parse_ber_sequence, parse_ber_utf8string, BerObject,
    BerObjectContent, Tag,
};
use napi::{
    bindgen_prelude::{BigInt, ToNapiValue},
    Error, JsUnknown, Result, Status, ValueType,
};

#[napi(js_name = "addOneHundred")]
pub fn plus_100(input: u32) -> u32 {
    input + 100
}

pub enum UniversalTag {
    Boolean = 0x01, // +
    Integer = 0x02, // +
    BitString = 0x03,
    OctetString = 0x04,
    Null = 0x05, // +
    ObjectID = 0x06,
    ObjectDescriptor = 0x07,
    External = 0x08,
    Real = 0x09,
    Enumerated = 0xA,
    EmbeddedPDV = 0xB,
    UTF8String = 0xC,
    RelativeObjectID = 0xD,
    Sequence = 0x10,
    Set = 0x11,
    NumericString = 0x12,
    PrintableString = 0x13, // +
    TelexString = 0x14,
    VideotexString = 0x15,
    IA5String = 0x16,
    UTCTime = 0x17,
    GeneralizedTime = 0x18,
    GraphicString = 0x19,
    VisibleString = 0x1A,
    GeneralString = 0x1B,
    UniversalString = 0x1C,
    ChracterString = 0x1D,
    BMPString = 0x1E,
}

/// Convert JS input into ASN1 BER encoded data.
///
/// See [`asn1_rs::asn1_types`]
///
/// # Examples
///
/// ## Basic usage
///
/// ```
///
/// ```
#[napi(js_name = "JStoASN1")]
pub fn js_to_asn1(data: JsUnknown) -> Result<Vec<u8>> {
    let mut writer = Vec::new();

    match data.get_type()? {
        ValueType::Boolean => Boolean::new(if data.coerce_to_bool()?.get_value()? {
            1
        } else {
            0
        })
        .write_der(&mut writer)
        .expect("serialization to boolean failed"),
        ValueType::BigInt => Integer::from_i64(data.coerce_to_number()?.get_int64()?)
            .write_der(&mut writer)
            .expect("serialization to bigint failed"),
        ValueType::Number => Integer::from_i32(data.coerce_to_number()?.get_int32()?)
            .write_der(&mut writer)
            .expect("serialization to integer failed"),
        ValueType::String => {
            PrintableString::new(&data.coerce_to_string()?.into_utf8()?.into_owned()?)
                .write_der(&mut writer)
                .expect("serialization to string failed")
        }
        ValueType::Unknown if data.is_array()? => {
            println!("{:?}", data.get_type());
            // let obj: Vec<JsUnknown> = data.coerce_to_object()?.to_vec();
            // writer = Sequence::from_iter_to_der(obj).unwrap();
            todo!()
        }
        ValueType::Unknown => {
            println!("{:?}", data.get_type());
            todo!()
        }
        ValueType::Object => todo!(),
        _ => {
            let msg = "unknown argument type".to_string();
            return Err(Error::new(Status::InvalidArg, msg));
        }
    };

    Ok(writer)
}

/// Convert raw data from BER encoding
fn get_ber_object<'a>(data: &'a [u8]) -> Result<BerObject<'a>> {
    if let Ok((_, header)) = ber_read_element_header(&data) {
        let (_, result) = match header.tag() {
            Tag::Null => parse_ber_null(&[]),
            Tag::Utf8String => parse_ber_utf8string(&data),
            Tag::PrintableString => parse_ber_printablestring(&data),
            Tag::Integer => parse_ber_integer(&data),
            Tag::Boolean => parse_ber_bool(&data),
            Tag::Sequence => parse_ber_sequence(&data),
            Tag::GeneralizedTime => parse_ber_generalizedtime(&data),
            tag => {
                println!("{:?}", tag);
                todo!()
            }
        }
        .unwrap_or((&[], BerObject::from(BerObjectContent::Null)));

        Ok(result)
    } else {
        let msg = String::from("{to do} {more conversions}");
        Err(Error::new(Status::InvalidArg, msg))
    }
}

#[napi]
#[derive(Debug)]
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
#[napi]
#[derive(Debug)]
pub struct ASN1toJS {
    js_type: JsType,
    data: Vec<u8>,
}

#[napi]
impl ASN1toJS {
    /// Create a new ANS1toJS instance from ASN1 encoded data.
    #[napi(constructor)]
    pub fn new(data: Vec<u8>) -> Self {
        if let Ok((_, header)) = ber_read_element_header(&data) {
            ASN1toJS {
                js_type: Self::fetch_type(header.tag()),
                data: data,
            }
        } else {
            ASN1toJS {
                js_type: JsType::Unknown,
                data: data,
            }
        }
    }

    /// Return a JsType from a BER tag
    pub fn fetch_type(tag: Tag) -> JsType {
        match tag {
            Tag::Boolean => JsType::Boolean,
            Tag::Integer => JsType::Integer,
            _ => JsType::Unknown,
        }
    }

    /// Get the JsType of the encoded data
    #[napi(getter)]
    pub fn get_type(&self) -> JsType {
        self.js_type
    }

    /// Create an instance of ANS1toJS from Base64 encoded data
    #[napi]
    pub fn from_base64(value: String) -> Result<Self> {
        Self::try_from(value)
    }

    /// Convert to an integer.
    #[napi]
    pub fn into_integer(&self) -> Result<i32> {
        if let Ok(data) = get_ber_object(&self.data) {
            Ok(data.as_i32().unwrap_or(0))
        } else {
            let msg = String::from("Invalid type");
            Err(Error::new(Status::GenericFailure, msg))
        }
    }

    /// Convert to a big integer.
    #[napi]
    pub fn into_big_integer(&self) -> Result<BigInt> {
        if let Ok(data) = get_ber_object(&self.data) {
            Ok(BigInt::from(data.as_u64().unwrap_or(0)))
        } else {
            let msg = String::from("Invalid type");
            Err(Error::new(Status::GenericFailure, msg))
        }
    }

    /// Convert to a boolean.
    #[napi]
    pub fn into_bool(&self) -> Result<bool> {
        if let Ok(data) = get_ber_object(&self.data) {
            Ok(data.as_bool().unwrap_or(false))
        } else {
            let msg = String::from("Invalid type");
            Err(Error::new(Status::GenericFailure, msg))
        }
    }

    /// Convert to a string.
    #[napi]
    pub fn into_string(&self) -> Result<String> {
        if let Ok(data) = get_ber_object(&self.data) {
            Ok(data.as_str().unwrap_or("").to_string())
        } else {
            let msg = String::from("Invalid type");
            Err(Error::new(Status::GenericFailure, msg))
        }
    }
}

impl TryFrom<String> for ASN1toJS {
    type Error = napi::Error;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl<'a> TryFrom<&'a str> for ASN1toJS {
    type Error = napi::Error;

    /// Create an instance of ANS1toJS from Base64 encoded data
    fn try_from(value: &'a str) -> std::result::Result<Self, Self::Error> {
        if let Ok(result) = base64::decode(value) {
            Self::try_from(result.as_slice())
        } else {
            let msg = String::from("Failed to decode Base64 data");
            Err(Error::new(Status::InvalidArg, msg))
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for ASN1toJS {
    type Error = napi::Error;

    /// Create an instance of ANS1toJS from Base64 encoded data
    fn try_from(value: &'a [u8]) -> std::result::Result<Self, Self::Error> {
        if let Ok(data) = get_ber_object(value)?.to_vec() {
            Ok(Self::new(data))
        } else {
            let msg = String::from("Failed to decode ASN1 BER data");
            Err(Error::new(Status::InvalidArg, msg))
        }
    }
}

#[cfg(test)]
mod test {
    use der_parser::ber::{parse_ber_sequence, Tag};

    use crate::get_ber_object;
    use crate::ASN1toJS;

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
    fn test_asn1_to_js_into_string() {
        let encoded = "EwR0ZXN0";
        let obj = ASN1toJS::from_base64(encoded.into()).expect("base64");

        assert_eq!(obj.into_string().unwrap(), "test");
    }

    #[test]
    fn test_js_to_asn1() {}
}

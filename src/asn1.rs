use anyhow::{bail, Error, Result};
use chrono::{DateTime, Utc};
use napi::{
    bindgen_prelude::{Array, Buffer},
    Env, JsBigInt,
};
use num_bigint::BigInt;
use rasn::{
    ber::decode,
    types::{Any, Class, OctetString, PrintableString, SequenceOf},
    Decode, Tag,
};

use crate::{
    asn1_to_js_unknown,
    objects::{ASN1BitString, ASN1ContextTag, ASN1Object, ASN1Set, ASN1OID},
    types::JsType,
    utils::{get_js_tag_from_asn1_tag, get_utc_date_time_from_asn1_milli, get_words_from_big_int},
    ASN1NAPIError,
};

/// Convert ASN1 BER encoded data to JS native types.
#[napi(js_name = "Asn1")]
#[derive(Hash, Eq, PartialEq, Debug)]
pub struct ASN1 {
    js_type: JsType,
    data: Vec<u8>,
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
            js_type: get_js_tag_from_asn1_tag(Tag::new(Class::Universal, bit)),
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
        get_utc_date_time_from_asn1_milli(&self.data)
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

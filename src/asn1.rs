use anyhow::{bail, Error, Result};
use chrono::{DateTime, Utc};
use napi::{
    bindgen_prelude::{Array, Buffer},
    Env, JsArrayBuffer, JsBigInt, JsUnknown,
};
use num_bigint::BigInt;
use rasn::{
    ber::{de::Error as BERError, decode, encode},
    de::Needed,
    types::{Any, Class, OctetString, PrintableString},
    Decode, Tag,
};

use crate::{
    get_js_array_from_asn_iter, get_js_big_int_from_big_int, get_js_context_tag_from_asn1_context,
    objects::{
        ASN1BitString, ASN1BitStringData, ASN1Context, ASN1ContextTag, ASN1Object, ASN1Set, ASN1OID,
    },
    types::{ASN1Data, JsType},
    utils::{get_utc_date_time_from_asn1_milli, get_vec_from_js_unknown},
    ASN1NAPIError,
};

/// Convert ASN1 BER encoded data to JS native types.
#[napi(js_name = "ASN1Decoder")]
#[derive(Eq, Clone, PartialEq, Debug)]
pub struct ASN1Decoder {
    tag: Tag,
    js_type: JsType,
    data: Vec<u8>,
}

#[napi(js_name = "ASN1Encoder")]
pub struct ASN1Encoder(ASN1Data);

#[napi(js_name = "ASN1Iterator")]
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ASN1Iterator {
    sequence: Vec<Any>,
    length: usize,
    index: usize,
}

#[napi]
impl ASN1Iterator {
    #[napi]
    pub fn len(&self) -> usize {
        self.length
    }
}

#[napi]
impl ASN1Encoder {
    /// Create a new ASN1Encoder instance from any ASN1 encodable type.
    #[napi(constructor)]
    pub fn js_new(
        #[napi(
            ts_arg_type = "BigInt | bigint | number | Date | ArrayBufferLike | Buffer | ASN1OID | ASN1Set | ASN1ContextTag | ASN1BitString | string | boolean | any[] | null"
        )]
        data: JsUnknown,
    ) -> Result<Self> {
        Ok(Self(ASN1Data::try_from(data)?))
    }

    /// Create a new ANS1toJS instance from ASN1Data.
    pub fn new(data: ASN1Data) -> Self {
        Self(data)
    }

    /// Encode ASN1Data to a Vec<u8> of ASN.1 encoded data.
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        if let Ok(data) = encode(&self.0) {
            Ok(data)
        } else {
            bail!(ASN1NAPIError::MalformedData)
        }
    }

    /// Encode the ASN.1 data as an array buffer.
    #[allow(unused_variables)]
    #[napi(js_name = "toBER", ts_return_type = "ArrayBuffer")]
    pub fn to_ber(&self, env: Env, size_only: Option<bool>) -> Result<JsArrayBuffer> {
        Ok(env.create_arraybuffer_with_data(self.encode()?)?.into_raw())
    }

    /// Encode the ASN.1 data to a ASN.1 encoded base64 encoded string.
    #[napi(js_name = "toBase64")]
    pub fn to_base64(&self) -> Result<String> {
        Ok(base64::encode(self.encode()?))
    }
}

#[napi]
impl ASN1Decoder {
    /// Js constructor
    #[napi(constructor)]
    pub fn js_new(
        #[napi(ts_arg_type = "string | null | number[] | Buffer | ArrayBuffer")] data: JsUnknown,
    ) -> Result<Self> {
        Ok(Self::new(get_vec_from_js_unknown(data)?))
    }

    /// Create a new ANS1toJS instance from ASN1 encoded data.
    pub fn new(data: Vec<u8>) -> Self {
        // Match constructed Sequence/Set tag
        let bit = match *data.first().unwrap_or(&0x5) as u32 {
            0x30 => 0x10,
            0x31 => 0x11,
            n => n,
        } as u32;

        let tag = if (0xa0..=0xbf).contains(&bit) {
            Tag::new(Class::Context, bit ^ 0xa0)
        } else {
            Tag::new(Class::Universal, bit)
        };

        ASN1Decoder {
            js_type: JsType::from(tag),
            tag,
            data,
        }
    }

    /// Get the JsType of the encoded data.
    pub fn get_js_type(&self) -> &JsType {
        &self.js_type
    }

    /// Get the Tag of the encoded data.
    pub fn get_tag(&self) -> &Tag {
        &self.tag
    }

    /// Get the raw ASN.1 data.
    pub fn get_raw(&self) -> &[u8] {
        &self.data
    }

    /// Create an instance of ANS1 from a buffer.
    #[napi]
    pub fn from_buffer(value: Buffer) -> Result<ASN1Decoder> {
        Self::try_from(Vec::<u8>::from(value))
    }

    /// Create an instance of ANS1 from Base64 encoded data.
    #[napi]
    pub fn from_base64(value: String) -> Result<ASN1Decoder> {
        if let Ok(result) = base64::decode(value) {
            Self::try_from(result.as_slice())
        } else {
            bail!(ASN1NAPIError::UnknownStringFormat)
        }
    }

    /// Create an instance of ANS1 from hex encoded data
    #[napi]
    pub fn from_hex(value: String) -> Result<ASN1Decoder> {
        if let Ok(result) = hex::decode(value) {
            Self::try_from(result.as_slice())
        } else {
            bail!(ASN1NAPIError::UnknownStringFormat)
        }
    }

    /// Decode ASN1 encoded data.
    pub(crate) fn decode<T: Decode>(&self) -> Result<T> {
        match decode::<T>(&self.data) {
            Ok(data) => Ok(data),
            Err(err) => match err {
                BERError::Incomplete {
                    needed: Needed::Size(val),
                } => {
                    let data = [..val].iter().fold(self.data.clone(), |mut data, _| {
                        data.push(0x00);
                        data
                    });
                    if let Ok(result) = decode(&data) {
                        Ok(result)
                    } else {
                        bail!(ASN1NAPIError::MalformedData)
                    }
                }
                _ => bail!(ASN1NAPIError::MalformedData),
            },
        }
    }

    /// Get a ASN1BitString object.
    pub(crate) fn get_raw_bit_string(&self) -> Result<ASN1BitStringData> {
        self.decode::<ASN1BitStringData>()
    }

    /// Get a Context object.
    pub(crate) fn get_context(&self) -> Result<ASN1Context> {
        self.decode::<ASN1Context>()
    }

    /// Decode into Any.
    pub(crate) fn into_any(self) -> Result<Any> {
        self.decode::<Any>()
    }

    /// Decode an object to an ASN1Object.
    pub(crate) fn into_object(self) -> Result<ASN1Object> {
        self.decode::<ASN1Object>()
    }

    /// Convert to a big integer.
    pub(crate) fn into_big_integer(self) -> Result<BigInt> {
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
        get_js_big_int_from_big_int(env, self.decode::<BigInt>()?)
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

    /// Convert to a JS ASN1BitString object.
    #[napi]
    pub fn into_bit_string(&self, env: Env) -> Result<ASN1BitString> {
        Ok(self.get_raw_bit_string()?.into_asn1_bitstring(env))
    }

    /// Convert to an Set object.
    #[napi]
    pub fn into_set(&self) -> Result<ASN1Set> {
        self.decode::<ASN1Set>()
    }

    /// Convert to an Context object.
    #[napi]
    pub fn into_context_tag(&self, env: Env) -> Result<ASN1ContextTag> {
        get_js_context_tag_from_asn1_context(env, self.get_context()?)
    }

    /// Convert a Sequence to an Array.
    #[napi(ts_return_type = "any[]")]
    pub fn into_array(&self, env: Env) -> Result<Array> {
        get_js_array_from_asn_iter(env, self.clone().into_iter())
    }
}

impl Iterator for ASN1Iterator {
    type Item = Result<ASN1Data>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(item) = self.sequence.get(self.index) {
            self.index += 1;
            Some(ASN1Data::try_from(ASN1Decoder::new(item.as_bytes().into())))
        } else {
            None
        }
    }
}

impl IntoIterator for ASN1Decoder {
    type Item = Result<ASN1Data>;

    type IntoIter = ASN1Iterator;

    /// Convert to an iterator for ASN1Data. Use this if you plan to apply
    /// functions to each result to maintain O(n) time complexity.
    ///
    /// # Examples
    ///
    /// ## Basic usage
    ///
    /// ```
    /// #[macro_use]
    /// extern crate asn1_napi_rs;
    /// use asn1_napi_rs::asn1::ASN1;
    ///
    /// fn sum_sequence(data: Vec<u8>) -> Result<i64, Box<dyn std::error::Error>> {
    ///     Ok(ASN1::new(data)
    ///         .into_iter()?
    ///         .map(|data| cast_data!(data, ASN1Data::Integer))
    ///         .sum())
    /// }
    ///
    /// let data = vec![
    ///     0x30, 0x0f, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03,
    ///     0x02, 0x01, 0x04, 0x02, 0x01, 0x05,
    /// ];
    ///
    /// assert_eq!(sum_sequence(data).unwrap(), [1, 2, 3, 4, 5].iter().sum());
    /// ```
    fn into_iter(self) -> Self::IntoIter {
        ASN1Iterator::from(self.decode::<Vec<Any>>().unwrap_or_default())
    }
}

impl From<Vec<Any>> for ASN1Iterator {
    fn from(sequence: Vec<Any>) -> Self {
        Self {
            length: sequence.len(),
            index: 0,
            sequence,
        }
    }
}

impl TryFrom<String> for ASN1Decoder {
    type Error = Error;

    /// Create an instance of ANS1toJS from Base64 or hex encoded data.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl<'a> TryFrom<&'a str> for ASN1Decoder {
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

impl<'a> TryFrom<&'a [u8]> for ASN1Decoder {
    type Error = Error;

    /// Create an instance of ANS1toJS from raw data.
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Ok(Self::new(value.into()))
    }
}

impl TryFrom<Vec<u8>> for ASN1Decoder {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use chrono::{DateTime, FixedOffset, TimeZone, Utc};
    use num_bigint::BigInt;
    use rasn::types::BitString;

    use crate::asn1::ASN1Decoder;
    use crate::asn1::ASN1Encoder;
    use crate::cast_data;
    use crate::objects::ASN1BitStringData;
    use crate::objects::ASN1Context;
    use crate::objects::ASN1Object;
    use crate::objects::ASN1Set;
    use crate::objects::ASN1OID;
    use crate::types::ASN1Data;
    use crate::types::JsType;

    const TEST_VOTE: &str = "MFEGCWCGSAFlAwQCCDBEBCCb0PJlcOIUeBZH8vNeObY9pg\
                             xw+6PUh6ku6n9k9VVYDgQge0hOYtjbsjyJqqx5m7D8iP+i\
                             6dLBTcFsl/kwxUkaO1k=";
    const TEST_BLOCK: &str = "MIHWAgEAAgIByAIBexgTMjAyMjA2MjIxODE4MDAuMjEwW\
                              gQiAALE/SPerrujysUeJZetilu60VeOZ29M3vyUsjGPdq\
                              agsgQguP6a3fMrNmLVzXptmUh0I8Otu5S3fX4PWWBDbWx\
                              Ed+IwLDAqAgEABCIAA8GUaJ5YXCd7B46iRMLXMtmmPOW5\
                              v3MD2DK+so3K1BuRAgEKAkEA66ba0QK07zVrshYkOF3cO\
                              aW61T1ckn9QymeSBE+yE7EJPDnrN6g54KxBaAjRVFlT3i\
                              Ze4qTtQfXRoCkhoCgzqg==";

    fn fixture_get_test_vote() -> Vec<ASN1Data> {
        vec![
            ASN1Data::Object(ASN1Object::Oid(ASN1OID::new("sha3-256"))),
            ASN1Data::Array(vec![
                ASN1Data::Bytes(
                    hex::decode(
                        "9bd0f26570e214781647f2f35e39b63da60c70\
                            fba3d487a92eea7f64f555580e",
                    )
                    .expect("hex"),
                ),
                ASN1Data::Bytes(
                    hex::decode(
                        "7b484e62d8dbb23c89aaac799bb0fc\
                            88ffa2e9d2c14dc16c97f930c5491a3b59",
                    )
                    .expect("hex"),
                ),
            ]),
        ]
    }

    fn fixture_get_test_block() -> Vec<ASN1Data> {
        vec![
            ASN1Data::Integer(0),
            ASN1Data::Integer(456),
            ASN1Data::Integer(123),
            ASN1Data::Date(DateTime::<FixedOffset>::from(
                Utc.ymd(2022, 6, 22).and_hms_milli(18, 18, 0, 210),
            )),
            ASN1Data::Bytes(
                hex::decode(
                    "0002C4FD23DEAEBBA3CAC51E2597AD8A5BBAD1578E6\
                     76F4CDEFC94B2318F76A6A0B2",
                )
                .expect("hex"),
            ),
            ASN1Data::Bytes(
                hex::decode(
                    "B8FE9ADDF32B3662D5CD7A6D99487423C3ADBB94B77\
                     D7E0F5960436D6C4477E2",
                )
                .expect("hex"),
            ),
            ASN1Data::Array(vec![ASN1Data::Array(vec![
                ASN1Data::Integer(0),
                ASN1Data::Bytes(
                    hex::decode(
                        "0003C194689E585C277B078EA244C2D732D9A63CE5B9BF7\
                         303D832BEB28DCAD41B91",
                    )
                    .expect("hex"),
                ),
                ASN1Data::Integer(10),
            ])]),
            ASN1Data::BigInt(
                BigInt::from_str(
                    "123420849842679662628402583993698371919475023\
                     865306400494192638014388787592329547816109951\
                     558088511082592942731994462782276923187529716\
                     58125549615746397098",
                )
                .expect("BigInt"),
            ),
        ]
    }

    #[test]
    fn test_asn1_into_bool() {
        let encoded_true = "AQH/";
        let encoded_false = "AQEA";

        let obj_true = ASN1Decoder::from_base64(encoded_true.into()).expect("base64");
        let obj_false = ASN1Decoder::from_base64(encoded_false.into()).expect("base64");

        assert!(obj_true.into_bool().unwrap());
        assert!(!obj_false.into_bool().unwrap());
    }

    #[test]
    fn test_asn1_into_integer() {
        let encoded = "AgEq";
        let obj = ASN1Decoder::from_base64(encoded.into()).expect("base64");

        assert_eq!(obj.into_integer().unwrap(), 42_i64);

        let encoded = "AgP/AAE=";
        let obj = ASN1Decoder::from_base64(encoded.into()).expect("base64");

        assert_eq!(obj.into_integer().unwrap(), -65535_i64);
    }

    #[test]
    fn test_asn1_into_big_integer() {
        let encoded = "AgkBAgMEBQYHCAk=";
        let obj = ASN1Decoder::from_base64(encoded.into()).expect("base64");

        assert_eq!(
            obj.into_big_integer().unwrap(),
            BigInt::from(18591708106338011145_i128)
        );
    }

    #[test]
    fn test_asn1_into_string() {
        let encoded = "EwR0ZXN0";
        let obj = ASN1Decoder::from_base64(encoded.into()).expect("base64");

        assert_eq!(obj.into_string().unwrap(), "test");
    }

    #[test]
    fn test_asn1_into_date() {
        let encoded = "GA8yMDIyMDkyNjEwMDAwMFo=";
        let obj = ASN1Decoder::from_base64(encoded.into()).expect("base64");

        assert_eq!(
            obj.into_date().unwrap(),
            Utc.ymd(2022, 9, 26).and_hms_milli(10, 0, 0, 0)
        );
    }

    #[test]
    fn test_asn1_into_bytes() {
        let encoded = "BAUBAgMEBQ==";
        let obj = ASN1Decoder::from_base64(encoded.into()).expect("base64");

        assert_eq!(
            obj.into_bytes().unwrap(),
            vec![0x01, 0x02, 0x03, 0x04, 0x05]
        );
    }

    #[test]
    fn test_asn1_into_oid() {
        let encoded = "BglghkgBZQMEAgE=";
        let obj = ASN1Decoder::from_base64(encoded.into()).expect("base64");

        assert_eq!(obj.into_oid().unwrap(), ASN1OID::new("sha256"));
    }

    #[test]
    fn test_asn1_into_set() {
        let encoded = "MQ0wCwYDVQQDEwR0ZXN0";
        let obj = ASN1Decoder::from_base64(encoded.into()).expect("base64");

        assert_eq!(
            obj.into_set().unwrap(),
            ASN1Set::new(ASN1OID::new("commonName"), "test")
        );
    }

    #[test]
    fn test_asn1_into_bit_string() {
        let encoded = "AwYAChAUIAk=";
        let obj = ASN1Decoder::from_base64(encoded.into()).expect("base64");

        assert_eq!(
            obj.get_raw_bit_string().unwrap(),
            ASN1BitStringData::new(BitString::from_vec(vec![0xa, 0x10, 0x14, 0x20, 0x9]))
        );
    }

    #[test]
    fn test_asn1_into_object() {
        let encoded = "MQ0wCwYDVQQDEwR0ZXN0";
        let obj = ASN1Decoder::from_base64(encoded.into()).expect("base64");

        assert_eq!(
            obj.into_set().unwrap(),
            ASN1Set::new(ASN1OID::new("commonName"), "test")
        );
    }

    #[test]
    fn test_asn1_into_sequence() {
        fn sum_sequence(data: Vec<u8>) -> Result<i64, Box<dyn std::error::Error>> {
            Ok(ASN1Decoder::new(data)
                .into_iter()
                .map(|result| cast_data!(result, Result::Ok))
                .map(|data| cast_data!(data, ASN1Data::Integer))
                .sum())
        }

        let data = vec![
            0x30, 0x0f, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03, 0x02, 0x01, 0x04,
            0x02, 0x01, 0x05,
        ];

        assert_eq!(sum_sequence(data).unwrap(), [1, 2, 3, 4, 5].iter().sum());
    }

    #[test]
    fn test_asn1_into_context_tag() {
        let encoded = "oFMwUQYJYIZIAWUDBAIIMEQEICr/S0giG9GX2MTM\
                             rxc3EIGys5PE8jr8r18mIzZ2zYQ6BCCDoM+00VOs\
                             NOWyS0x0/VCAPCC3p6iC3JSwDdTpMH/5rw==";
        let obj = ASN1Decoder::from_base64(encoded.into()).unwrap();
        let oid = ASN1Object::Oid(ASN1OID::new("sha3-256"));

        let contents = ASN1Data::Array(vec![
            ASN1Data::Object(oid),
            ASN1Data::Array(vec![
                ASN1Data::Bytes(vec![
                    0x2a, 0xff, 0x4b, 0x48, 0x22, 0x1b, 0xd1, 0x97, 0xd8, 0xc4, 0xcc, 0xaf, 0x17,
                    0x37, 0x10, 0x81, 0xb2, 0xb3, 0x93, 0xc4, 0xf2, 0x3a, 0xfc, 0xaf, 0x5f, 0x26,
                    0x23, 0x36, 0x76, 0xcd, 0x84, 0x3a,
                ]),
                ASN1Data::Bytes(vec![
                    0x83, 0xa0, 0xcf, 0xb4, 0xd1, 0x53, 0xac, 0x34, 0xe5, 0xb2, 0x4b, 0x4c, 0x74,
                    0xfd, 0x50, 0x80, 0x3c, 0x20, 0xb7, 0xa7, 0xa8, 0x82, 0xdc, 0x94, 0xb0, 0x0d,
                    0xd4, 0xe9, 0x30, 0x7f, 0xf9, 0xaf,
                ]),
            ]),
        ]);

        assert_eq!(obj.get_context().unwrap(), ASN1Context::new(0, contents));
    }

    #[test]
    fn test_asn1_block_into_sequence() {
        let block = fixture_get_test_block();
        let obj = ASN1Decoder::from_base64(TEST_BLOCK.into()).expect("base64");
        let js_type = *obj.get_js_type();

        assert_eq!(js_type, JsType::Sequence);

        obj.into_iter().enumerate().for_each(|(i, data)| {
            assert_eq!(data.unwrap(), block[i]);
        });
    }

    #[test]
    fn test_asn1_vote_into_sequence() {
        let vote = fixture_get_test_vote();
        let obj = ASN1Decoder::from_base64(TEST_VOTE.into()).expect("base64");
        let js_type = *obj.get_js_type();

        assert_eq!(js_type, JsType::Sequence);

        obj.into_iter().enumerate().for_each(|(i, data)| {
            assert_eq!(data.unwrap(), vote[i]);
        });
    }

    #[test]
    fn test_asn1_encoder_to_base64() {
        let block = fixture_get_test_block();
        let encoder = ASN1Encoder::new(ASN1Data::Array(block));

        assert_eq!(encoder.to_base64().unwrap(), TEST_BLOCK);
    }
}

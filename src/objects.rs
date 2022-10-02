use anyhow::{bail, Error, Result};
use napi::{JsBuffer, JsObject, JsString, JsUnknown};
use num_bigint::BigInt;
use rasn::{
    de::Error as rasnDeError,
    enc::Error as rasnEncError,
    types::{BitString, ObjectIdentifier, Oid, PrintableString},
    AsnType, Decode, Decoder, Encode, Encoder, Tag,
};

use crate::{
    constants::*,
    types::ASN1Data,
    utils::{get_buffer_from_js, get_integer_from_js},
    ASN1NAPIError,
};

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
trait ASNAny: AsnType + Decode + Encode {}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ASN1Object {
    ASN1OID(ASN1OID),
    ASN1Set(ASN1Set),
    ASN1BitString(ASN1BitString),
    ASN1ContextTag(ASN1ContextTag),
}

/// ANS1 OID.
#[napi(object, js_name = "ASN1OID")]
#[derive(Hash, Clone, Eq, PartialEq, Debug)]
pub struct ASN1OID {
    pub r#type: &'static str,
    pub oid: String,
}

/// ANS1 Set.
#[napi(object, js_name = "ASN1Set")]
#[derive(Hash, Clone, Eq, PartialEq, Debug)]
pub struct ASN1Set {
    pub r#type: &'static str,
    pub name: ASN1OID,
    pub value: String,
}

/// ANS1 Context Tag.
#[napi(object, js_name = "ASN1ContextTag")]
#[derive(Hash, Clone, Eq, PartialEq, Debug)]
pub struct ASN1ContextTag {
    pub r#type: &'static str,
    pub value: i64,
    pub data: Vec<u8>,
}

/// ANS1 bitstring.
#[napi(object, js_name = "ASN1BitString")]
#[derive(Hash, Clone, Eq, PartialEq, Debug)]
pub struct ASN1BitString {
    pub r#type: &'static str,
    pub value: Vec<u8>,
}

/// ANS1 Sequence.
#[napi(object, js_name = "ASN1Sequence")]
pub struct ASN1Sequence {
    pub r#type: &'static str,
}

/// Get an oid as u32 words from a canonically named identifier.
fn get_oid_from_name<T: AsRef<str>>(name: T) -> Result<&'static [u32]> {
    if let Some(oid) = NAME_TO_OID_MAP.get(name.as_ref()) {
        Ok(*oid)
    } else {
        bail!(ASN1NAPIError::UnknownOid)
    }
}

/// Get an identifer string from an Oid.
fn get_oid_string_from_oid(oid: &Oid) -> String {
    oid.iter()
        .map(|&e| e.to_string())
        .collect::<Vec<String>>()
        .join(".")
}

/// Get a canonical name from an Oid.
fn get_name_from_oid(oid: &Oid) -> Result<&str> {
    if let Some(name) = OID_TO_NAME_MAP.get(&get_oid_string_from_oid(oid)) {
        Ok(*name)
    } else {
        bail!(ASN1NAPIError::UnknownOid)
    }
}

/// Get a canonical name from an Oid.
fn get_name_from_oid_string<T: AsRef<str>>(oid: T) -> Result<&'static str> {
    if let Some(name) = OID_TO_NAME_MAP.get(oid.as_ref()) {
        Ok(*name)
    } else {
        bail!(ASN1NAPIError::UnknownOid)
    }
}

pub trait TypedObject<'a> {
    const TYPE: &'a str;

    fn get_type() -> &'a str {
        Self::TYPE
    }
}

impl<'a> TypedObject<'a> for ASN1BitString {
    const TYPE: &'a str = "bitstring";
}

impl<'a> TypedObject<'a> for ASN1OID {
    const TYPE: &'a str = "oid";
}

impl<'a> TypedObject<'a> for ASN1Set {
    const TYPE: &'a str = "set";
}

impl<'a> TypedObject<'a> for ASN1Sequence {
    const TYPE: &'a str = "sequence";
}

impl<'a> TypedObject<'a> for ASN1ContextTag {
    const TYPE: &'a str = "context";
}

#[napi]
impl ASN1ContextTag {
    #[napi(getter)]
    pub fn contains(&self) -> Result<u32> {
        todo!()
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
                        r#type: Self::TYPE,
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

impl Encode for ASN1Object {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, _: Tag) -> Result<(), E::Error> {
        match self {
            ASN1Object::ASN1OID(obj) => obj.encode(encoder),
            ASN1Object::ASN1Set(obj) => obj.encode(encoder),
            ASN1Object::ASN1BitString(obj) => obj.encode(encoder),
            ASN1Object::ASN1ContextTag(obj) => obj.encode(encoder),
        }
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

impl Encode for ASN1Data {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, _: Tag) -> Result<(), E::Error> {
        match self {
            ASN1Data::Boolean(val) => {
                encoder.encode_bool(Tag::BOOL, *val)?;
                Ok(())
            }
            ASN1Data::BigInt(val) => {
                encoder.encode_integer(Tag::INTEGER, val)?;
                Ok(())
            }
            ASN1Data::Integer(val) => {
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
                encoder.encode_generalized_time(Tag::GENERALIZED_TIME, &val.to_owned())?;
                Ok(())
            }
            ASN1Data::Object(obj) => match obj {
                ASN1Object::ASN1OID(oid) => oid.encode(encoder),
                ASN1Object::ASN1BitString(bstring) => bstring.encode(encoder),
                ASN1Object::ASN1Set(set) => set.encode(encoder),
                ASN1Object::ASN1ContextTag(context) => context.encode(encoder),
            },
            ASN1Data::Array(arr) => arr.encode(encoder),
            ASN1Data::Unknown(any) => any.encode(encoder),
            ASN1Data::Null => Err(<E as Encoder>::Error::custom(
                ASN1NAPIError::UnknownArgument,
            )),
        }
    }
}

impl Decode for ASN1Data {
    fn decode_with_tag<D: Decoder>(decoder: &mut D, _: Tag) -> Result<Self, D::Error> {
        if let Ok(any) = decoder.decode_any() {
            println!("{:?}", any);
            todo!()
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

impl<'a> From<&'a [u8]> for ASN1BitString {
    /// Convert bytes into an ASN1BitString instance.
    /// TODO
    /// # Examples
    ///
    /// ## Basic usage
    ///
    /// ```
    ///
    /// ```
    fn from(value: &'a [u8]) -> Self {
        Self {
            r#type: Self::TYPE,
            value: value.into(),
        }
    }
}

impl From<Vec<u8>> for ASN1BitString {
    /// Convert an owned byte array into an ASN1BitString instance.
    fn from(value: Vec<u8>) -> Self {
        Self {
            r#type: Self::TYPE,
            value,
        }
    }
}

impl From<BitString> for ASN1BitString {
    /// Convert a BitString into an ASN1BitString instance.
    fn from(value: BitString) -> Self {
        Self::from(value.into_vec())
    }
}

impl TryFrom<JsObject> for ASN1BitString {
    type Error = Error;

    /// Attempt to convert a JsObject instance into an ASN1BitString instance.
    fn try_from(value: JsObject) -> Result<Self, Self::Error> {
        Self::try_from(value.get_named_property::<JsBuffer>(ASN1_OBJECT_VALUE_KEY)?)
    }
}

impl TryFrom<JsBuffer> for ASN1BitString {
    type Error = Error;

    /// Attempt to convert a JsBuffer instance into an ASN1BitString instance.
    fn try_from(value: JsBuffer) -> Result<Self, Self::Error> {
        Ok(Self {
            r#type: Self::TYPE,
            value: value.into_value()?.to_vec(),
        })
    }
}

impl<'a> TryFrom<&'a [u32]> for ASN1OID {
    type Error = Error;

    /// Attempt to convert words into an ASN1OID instance.
    fn try_from(value: &'a [u32]) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Ok(Self {
                r#type: Self::TYPE,
                oid: get_name_from_oid_string("")?.into(),
            })
        } else if let Some(oid) = Oid::new(value) {
            Ok(Self {
                r#type: Self::TYPE,
                oid: get_name_from_oid(oid)?.into(),
            })
        } else {
            bail!(ASN1NAPIError::UnknownOid)
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for ASN1OID {
    type Error = Error;

    /// Attempt to convert bytes into an ASN1BitString instance.
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Self::try_from(value.iter().map(|&e| e as u32).collect::<Vec<u32>>())
    }
}

impl TryFrom<Vec<u32>> for ASN1OID {
    type Error = Error;

    /// Attempt to convert owned words into an ASN1OID instance.
    fn try_from(value: Vec<u32>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl TryFrom<JsObject> for ASN1OID {
    type Error = Error;

    /// Attempt to convert a JsObject instance into an ASN1OID instance.
    fn try_from(value: JsObject) -> Result<Self, Self::Error> {
        let oid = value.get_named_property::<JsString>(ASN1OID::TYPE)?;
        let name = oid.into_utf8()?;

        Self::try_from(name.as_str()?)
    }
}

impl<'a> TryFrom<&'a str> for ASN1OID {
    type Error = Error;

    /// Attempt to convert a string into an ASN1OID instance.
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        if get_oid_from_name(value).is_ok() {
            Ok(Self {
                r#type: Self::TYPE,
                oid: value.to_string(),
            })
        } else {
            bail!(ASN1NAPIError::UnknownOid)
        }
    }
}

impl TryFrom<String> for ASN1OID {
    type Error = Error;

    /// Attempt to convert an owned string into an ASN1OID instance.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl TryFrom<JsObject> for ASN1Set {
    type Error = Error;

    /// Attempt to convert a JsObject instance into an ASN1Set instance.
    fn try_from(value: JsObject) -> Result<Self, Self::Error> {
        Ok(Self {
            r#type: Self::TYPE,
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

    /// Attempt to convert a JsObject instance into an ASN1ContextTag instance.
    fn try_from(value: JsObject) -> Result<Self, Self::Error> {
        Ok(Self {
            r#type: Self::TYPE,
            value: get_integer_from_js(value.get_named_property::<JsUnknown>("name")?)?,
            data: get_buffer_from_js(value.get_named_property::<JsUnknown>("data")?)?,
        })
    }
}

#[cfg(test)]
mod test {
    use super::ASN1OID;
    use crate::objects::TypedObject;

    #[test]
    fn test_asn1oid_try_from_string() {
        let input = "sha3-256WithEcDSA";
        let result = ASN1OID {
            r#type: ASN1OID::TYPE,
            oid: input.into(),
        };

        assert_eq!(ASN1OID::try_from(input).unwrap(), result);
    }

    #[test]
    fn test_asn1oid_try_from_words() {
        let input = vec![2, 23, 42, 2, 7, 11];
        let result = ASN1OID {
            r#type: ASN1OID::TYPE,
            oid: "account".into(),
        };

        assert_eq!(ASN1OID::try_from(input).unwrap(), result);

        let input = vec![];
        let result = ASN1OID {
            r#type: ASN1OID::TYPE,
            oid: "sha3-256WithEd25519".into(),
        };

        assert_eq!(ASN1OID::try_from(input).unwrap(), result);
    }
}

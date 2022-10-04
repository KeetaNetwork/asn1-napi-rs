use anyhow::{bail, Error, Result};
use napi::{Env, JsBuffer, JsNumber, JsObject, JsString, JsUnknown};
use rasn::{
    ber::decode,
    de::Error as rasnDeError,
    enc::Error as rasnEncError,
    types::{BitString, Class, ConstOid, ObjectIdentifier, Oid, Open, PrintableString, SequenceOf},
    AsnType, Decode, Decoder, Encode, Encoder, Tag,
};

use crate::{
    constants::*,
    types::{ASN1Data, TBSCertificateContexts},
    utils::{get_js_uknown_from_asn_data, get_oid_elements_from_string},
    ASN1NAPIError,
};

/// HashMap for names to OID
static NAME_TO_OID_MAP: phf::Map<&'static str, &'static [u32]> = phf_map! {
    "sha256" => &[2, 16, 840, 1, 101, 3, 4, 2, 1],
    "sha3-256" => &[2, 16, 840, 1, 101, 3, 4, 2, 8],
    "sha3-256WithEcDSA" => &[2, 16, 840, 1, 101, 3, 4, 3, 10],
    "sha256WithEcDSA" => &[1, 2, 840, 10045, 4, 3, 2],
    "ecdsa" => &[1, 2, 840, 10045, 2, 1],
    "ed25519" => &[1, 3, 101, 112],
    "secp256k1" => &[1, 3, 132, 0, 10],
    "account" => &[2, 23, 42, 2, 7, 11],
    "serialNumber" => &[2, 5, 4, 5],
    "member" => &[2, 5, 4, 31],
    "commonName" => &[2, 5, 4, 3],
    "hash" => &[1, 3, 6, 1, 4, 1, 8301, 3, 2, 2, 1, 1],
    "hashData" => &[2, 16, 840, 1, 101, 3, 3, 1, 3],
    // Default
    "sha3-256WithEd25519" => &[],
};

/// HashMap for an OID string to name
static OID_TO_NAME_MAP: phf::Map<&'static str, &'static str> = phf_map! {
    "2.16.840.1.101.3.4.2.1" => "sha256",
    "2.16.840.1.101.3.4.2.8" => "sha3-256",
    "2.16.840.1.101.3.4.3.10" => "sha3-256WithEcDSA",
    "1.2.840.10045.4.3.2" => "sha256WithEcDSA",
    "1.2.840.10045.2.1" => "ecdsa",
    "1.3.101.112" => "ed25519",
    "1.3.132.0.10" => "secp256k1",
    "2.23.42.2.7.11" => "account",
    "2.5.4.5" => "serialNumber",
    "2.5.4.31" => "member",
    "2.5.4.3" => "commonName",
    "1.3.6.1.4.1.8301.3.2.2.1.1" => "hash",
    "2.16.840.1.101.3.3.1.3" => "hashData",
    // Default
    "" => "sha3-256WithEd25519",
};
trait ASNAny: AsnType + Decode + Encode {}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum ASN1Object {
    Oid(ASN1OID),
    Set(ASN1Set),
    BitString(ASN1BitString),
    Context(ASN1Context),
}

/// ANS1 Context.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ASN1Context {
    pub value: i64,
    pub contains: TBSCertificateContexts,
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

/// ANS1 bitstring.
#[napi(object, js_name = "ASN1BitString")]
#[derive(Hash, Clone, Eq, PartialEq, Debug)]
pub struct ASN1BitString {
    pub r#type: &'static str,
    pub value: Vec<u8>,
}

/// ANS1 Context.
#[napi(object, js_name = "ASN1ContextTag")]
pub struct ASN1ContextTag {
    pub r#type: &'static str,
    pub value: i64,
    pub contains: JsUnknown,
}

/// ANS1 Sequence.
#[napi(object, js_name = "ASN1Sequence")]
pub struct ASN1Sequence {
    pub r#type: &'static str,
}

/// TBSCertificate Version
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct TBSCertificateVersion {
    pub oid: ASN1OID,
    pub data: SequenceOf<ASN1Data>,
}

/// TBSCertificate Extensions
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct TBSCertificateExtension {
    pub oid: ASN1OID,
    pub critical: bool,
    pub value: Vec<u8>,
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

impl ASN1OID {
    /// Create a new instance of ASNOID from a string.
    pub fn new<T: AsRef<str>>(oid: T) -> Self {
        Self {
            r#type: Self::TYPE,
            oid: oid.as_ref().into(),
        }
    }
}

impl ASN1BitString {
    /// Create a new instance of ASNOID from a string.
    pub fn new<T: AsRef<[u8]>>(value: T) -> Self {
        Self {
            r#type: Self::TYPE,
            value: value.as_ref().into(),
        }
    }
}

impl ASN1Set {
    /// Create a new instance of an ASN1Set from an ASN1OID and value.
    pub fn new<T: ToString>(name: ASN1OID, value: T) -> Self {
        Self {
            r#type: Self::TYPE,
            value: value.to_string(),
            name,
        }
    }
}

impl ASN1Context {
    /// Create a new instance of an ASN1Context from an i64 and ASN1Data.
    pub fn new(value: i64, data: ASN1Data) -> Result<Self> {
        if let ASN1Data::Array(data) = data {
            let contains = TBSCertificateContexts::new(value, data)?;

            Ok(Self { value, contains })
        } else {
            bail!(ASN1NAPIError::InvalidContextNonSequence)
        }
    }
}

impl Default for ASN1OID {
    /// Get a default implementation of an ASN1OID.
    fn default() -> Self {
        Self::new(get_name_from_oid_string("").expect("oid default"))
    }
}

impl TBSCertificateVersion {
    pub fn new(data: Vec<ASN1Data>) -> Result<Self> {
        let oid = if let Some(ASN1Data::Object(ASN1Object::Oid(oid))) = data.get(0) {
            oid.to_owned()
        } else {
            bail!(ASN1NAPIError::UnknownOid)
        };

        let data = if let Some(ASN1Data::Array(data)) = data.get(1) {
            data.to_owned()
        } else {
            bail!(ASN1NAPIError::UnknownOid)
        };

        Ok(Self { oid, data })
    }
}

impl TBSCertificateExtension {
    pub fn new(data: Vec<ASN1Data>) -> Result<Self> {
        if let Some(ASN1Data::Array(data)) = data.get(0) {
            let oid = if let Some(ASN1Data::Object(ASN1Object::Oid(oid))) = data.get(0) {
                oid.to_owned()
            } else {
                bail!(ASN1NAPIError::UnknownOid)
            };

            let critical = if let Some(ASN1Data::Boolean(data)) = data.get(1) {
                *data
            } else {
                bail!(ASN1NAPIError::UnexpectedSequenceValue)
            };

            let value = if let Some(ASN1Data::Bytes(data)) = data.get(2) {
                data.to_owned()
            } else {
                bail!(ASN1NAPIError::UnexpectedSequenceValue)
            };

            Ok(Self {
                oid,
                critical,
                value,
            })
        } else {
            bail!(ASN1NAPIError::UknownContext)
        }
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

impl<'a> TypedObject<'a> for ASN1Context {
    const TYPE: &'a str = "context";
}

impl<'a> TypedObject<'a> for ASN1ContextTag {
    const TYPE: &'a str = "context";
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

impl AsnType for ASN1Object {
    const TAG: Tag = Tag::SEQUENCE;
}

impl AsnType for ASN1Context {
    const TAG: Tag = Tag::new(Class::Context, 0x0);
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
        if self.oid.contains(['.']) {
            if let Ok(result) = get_oid_elements_from_string(&self.oid) {
                encoder.encode_object_identifier(tag, &result)?;
                Ok(())
            } else {
                Err(<E as Encoder>::Error::custom(ASN1NAPIError::UnknownOid))
            }
        } else {
            if let Ok(result) = get_oid_from_name(&self.oid) {
                encoder.encode_object_identifier(tag, result)?;
                Ok(())
            } else {
                Err(<E as Encoder>::Error::custom(ASN1NAPIError::UnknownOid))
            }
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
                    Ok(Self::new(oid, value.as_str()))
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
            ASN1Object::Oid(obj) => obj.encode(encoder),
            ASN1Object::Set(obj) => obj.encode(encoder),
            ASN1Object::BitString(obj) => obj.encode(encoder),
            ASN1Object::Context(obj) => obj.encode(encoder),
        }
    }
}

impl Encode for ASN1Context {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, _: Tag) -> Result<(), E::Error> {
        self.contains.encode(encoder)
    }
}

impl Decode for ASN1Context {
    fn decode_with_tag<D: Decoder>(decoder: &mut D, _: Tag) -> Result<Self, D::Error> {
        println!("{:?}", Vec::<Open>::decode(decoder)?);
        let contains = TBSCertificateContexts::decode(decoder)?;
        let value = i64::from(&contains);

        Ok(Self { value, contains })
    }
}

// TODO Figure out a better way to handle this
impl Decode for ASN1Object {
    fn decode_with_tag<D: Decoder>(decoder: &mut D, _: Tag) -> Result<Self, D::Error> {
        if let Ok(obj) = ASN1Set::decode_with_tag(decoder, ASN1Set::TAG) {
            Ok(ASN1Object::Set(obj))
        } else if let Ok(obj) = ASN1OID::decode_with_tag(decoder, ASN1OID::TAG) {
            Ok(ASN1Object::Oid(obj))
        } else if let Ok(obj) = ASN1BitString::decode_with_tag(decoder, ASN1BitString::TAG) {
            Ok(ASN1Object::BitString(obj))
        } else if let Ok(obj) = ASN1Context::decode(decoder) {
            Ok(ASN1Object::Context(obj))
        } else {
            Err(<D as Decoder>::Error::custom(ASN1NAPIError::UnknownObject))
        }
    }
}

impl Encode for ASN1Data {
    fn encode_with_tag<E: Encoder>(&self, encoder: &mut E, tag: Tag) -> Result<(), E::Error> {
        match self {
            ASN1Data::Array(arr) => arr.encode(encoder),
            ASN1Data::Object(obj) => match obj {
                ASN1Object::Oid(oid) => oid.encode(encoder),
                ASN1Object::BitString(bstring) => bstring.encode(encoder),
                ASN1Object::Set(set) => set.encode(encoder),
                ASN1Object::Context(context) => context.encode(encoder),
            },
            ASN1Data::Unknown(any) => any.encode(encoder),
            ASN1Data::Null => encoder.encode_null(tag).map(|_| ()),
            _ => {
                if let Ok(open) = Open::try_from(self) {
                    open.encode(encoder)
                } else {
                    Err(<E as Encoder>::Error::custom(
                        ASN1NAPIError::UnknownJsArgument,
                    ))
                }
            }
        }
    }
}

impl Decode for ASN1Data {
    fn decode_with_tag<D: Decoder>(decoder: &mut D, _: Tag) -> Result<Self, D::Error> {
        if let Ok(decoded) = decode::<Open>(decoder.decode_any()?.as_bytes()) {
            if let Ok(data) = ASN1Data::try_from(decoded) {
                Ok(data)
            } else {
                Err(<D as Decoder>::Error::custom(
                    ASN1NAPIError::UnknownJsArgument,
                ))
            }
        } else {
            Err(<D as Decoder>::Error::custom(
                ASN1NAPIError::UnknownJsArgument,
            ))
        }
    }
}

impl AsRef<[u32]> for ASN1OID {
    fn as_ref(&self) -> &[u32] {
        get_oid_from_name(&self.oid).unwrap()
    }
}

impl From<&TBSCertificateContexts> for i64 {
    fn from(value: &TBSCertificateContexts) -> Self {
        match value {
            TBSCertificateContexts::Version(_) => 0,
            TBSCertificateContexts::Extension(_) => 3,
        }
    }
}

impl From<ASN1OID> for ObjectIdentifier {
    fn from(data: ASN1OID) -> Self {
        if let Some(oid) = Oid::new(data.as_ref()) {
            ObjectIdentifier::from(oid)
        } else {
            ObjectIdentifier::from(ConstOid(&[0]))
        }
    }
}

impl<'a> From<&'a [u8]> for ASN1BitString {
    /// Convert bytes into an ASN1BitString instance.
    fn from(value: &'a [u8]) -> Self {
        Self::new(value)
    }
}

impl From<Vec<u8>> for ASN1BitString {
    /// Convert an owned byte array into an ASN1BitString instance.
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

impl From<BitString> for ASN1BitString {
    /// Convert a BitString into an ASN1BitString instance.
    fn from(value: BitString) -> Self {
        Self::from(value.into_vec())
    }
}

impl TryFrom<(Env, ASN1Context)> for ASN1ContextTag {
    type Error = Error;

    fn try_from(value: (Env, ASN1Context)) -> Result<Self, Self::Error> {
        let (env, data) = value;

        Ok(Self {
            r#type: Self::TYPE,
            value: data.value,
            contains: get_js_uknown_from_asn_data(env, ASN1Data::try_from(data.contains)?)?,
        })
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
        Ok(Self::new(value.into_value()?))
    }
}

impl<'a> TryFrom<&'a [u32]> for ASN1OID {
    type Error = Error;

    /// Attempt to convert words into an ASN1OID instance.
    fn try_from(value: &'a [u32]) -> Result<Self, Self::Error> {
        if let Some(oid) = Oid::new(value) {
            Ok(Self::new(get_name_from_oid(oid)?))
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
        let name = oid.into_utf16()?;

        Self::try_from(name.as_str()?)
    }
}

impl<'a> TryFrom<&'a str> for ASN1OID {
    type Error = Error;

    /// Attempt to convert a string into an ASN1OID instance.
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        if value.contains(['.']) && Oid::new(&get_oid_elements_from_string(value)?).is_some() {
            Ok(Self::new(value))
        } else if get_oid_from_name(value).is_ok() {
            Ok(Self::new(value))
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
        let oid = ASN1OID::try_from(value.get_named_property::<JsObject>("name")?)?;
        let value = value
            .get_named_property::<JsString>(ASN1_OBJECT_VALUE_KEY)?
            .into_utf16()?;

        Ok(Self::new(oid, value.as_str()?))
    }
}

impl TryFrom<JsObject> for ASN1Context {
    type Error = Error;

    /// Attempt to convert a JsObject instance into an ASN1Context instance.
    fn try_from(obj: JsObject) -> Result<Self, Self::Error> {
        let value = obj.get_named_property::<JsNumber>("value")?;
        let context = TBSCertificateContexts::try_from(obj)?;

        Ok(Self {
            value: value.get_int64()?,
            contains: context,
        })
    }
}

#[cfg(test)]
mod test {
    use super::ASN1OID;

    #[test]
    fn test_asn1oid_try_from_string() {
        let input = "sha3-256WithEcDSA";
        let result = ASN1OID::new(input);

        assert_eq!(ASN1OID::try_from(input).unwrap(), result);

        let input = "1.2.3.4";
        let result = ASN1OID::new(input);

        assert_eq!(ASN1OID::try_from(input).unwrap(), result);
    }

    #[test]
    fn test_asn1oid_try_from_words() {
        let input = vec![2, 23, 42, 2, 7, 11];
        let result = ASN1OID::new("account");

        assert_eq!(ASN1OID::try_from(input).unwrap(), result);

        let input = vec![];
        let result = ASN1OID::new("sha3-256WithEd25519");

        assert_eq!(ASN1OID::try_from(input).unwrap(), result);
    }
}

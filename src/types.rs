use anyhow::{bail, Error};
use chrono::{DateTime, FixedOffset};
use num_bigint::BigInt;

use crate::{asn1::ASN1, constants::*, objects::ASN1Object, ASN1NAPIError};

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

/// Integer or Big Integer
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum ASN1Number {
    Integer(i64),
    BigInt(BigInt),
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

impl ToString for ASN1ObjectType {
    /// Return the String representation of an ASN1ObjectType.
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

impl From<ASN1ObjectType> for &str {
    /// Return the String representation of an ASN1ObjectType.
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
    /// Return ASN1ObjectType from a string.
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

#[cfg(test)]
mod test {
    use num_bigint::BigInt;

    use crate::{types::ASN1Number, ASN1};

    #[test]
    fn test_asn1number_try_from_asn1() {
        let asn1 = ASN1::new(vec![2, 1, 42]).unwrap();
        let input = ASN1Number::try_from(asn1).unwrap();

        assert_eq!(input, ASN1Number::Integer(42));

        let asn1 = ASN1::new(vec![2, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
        let input = ASN1Number::try_from(asn1).unwrap();

        assert_eq!(
            input,
            ASN1Number::BigInt(BigInt::from(18591708106338011145_i128))
        );
    }
}

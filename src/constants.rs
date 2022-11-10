/// Key string for "type" attribute of objects.
pub(crate) const ASN1_OBJECT_TYPE_KEY: &str = "type";
/// Key string for "value" attribute of objects.
pub(crate) const ASN1_OBJECT_VALUE_KEY: &str = "value";
/// Key string for "name" attribute of objects.
pub(crate) const ASN1_OBJECT_NAME_KEY: &str = "name";
/// ASN1 Date format with milliseconds.
pub(crate) const ASN1_DATE_TIME_GENERAL_FORMAT: &str = "%Y%m%d%H%M%S%.3fZ";
/// ASN1 Date format with milliseconds.
pub(crate) const ASN1_DATE_TIME_UTC_FORMAT: &str = "%y%m%d%H%M%SZ";
/// ASN1 null data.
pub(crate) const ASN1_NULL: &[u8] = &[0x05, 0x00];

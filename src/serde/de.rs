// SPDX-License-Identifier: Apache-2.0
use crate::{
    AttrId, Multisig,
    ms::{self, Attributes},
};
use core::fmt;
use multi_codec::Codec;
use multi_util::EncodedVarbytes;
use serde::{
    Deserialize, Deserializer,
    de::{Error, MapAccess, Visitor},
};

/// Deserialize instance of [`crate::AttrId`]
impl<'de> Deserialize<'de> for AttrId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AttrVisitor;

        impl<'de> Visitor<'de> for AttrVisitor {
            type Value = AttrId;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                write!(fmt, "borrowed str, str, String, or u8")
            }

            fn visit_u8<E>(self, c: u8) -> Result<Self::Value, E>
            where
                E: Error,
            {
                AttrId::try_from(c).map_err(|e| Error::custom(e.to_string()))
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                AttrId::try_from(s).map_err(|e| Error::custom(e.to_string()))
            }

            fn visit_borrowed_str<E>(self, s: &'de str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                AttrId::try_from(s).map_err(|e| Error::custom(e.to_string()))
            }

            fn visit_string<E>(self, s: String) -> Result<Self::Value, E>
            where
                E: Error,
            {
                AttrId::try_from(s.as_str()).map_err(|e| Error::custom(e.to_string()))
            }
        }

        deserializer.deserialize_any(AttrVisitor)
    }
}

/// Deserialize instance of [`crate::Multisig`]
impl<'de> Deserialize<'de> for Multisig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["codec", "message", "attributes"];

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Codec,
            Message,
            Attributes,
        }

        struct MultisigVisitor;

        impl<'de> Visitor<'de> for MultisigVisitor {
            type Value = Multisig;

            fn expecting(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt.write_str("struct Multisig")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut codec = None;
                let mut message = None;
                let mut attributes = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Codec => {
                            if codec.is_some() {
                                return Err(Error::duplicate_field("codec"));
                            }
                            let c: Codec = map.next_value()?;
                            codec = Some(c);
                        }
                        Field::Message => {
                            if message.is_some() {
                                return Err(Error::duplicate_field("message"));
                            }
                            let m: EncodedVarbytes = map.next_value()?;
                            message = Some(m.to_inner().to_inner());
                        }
                        Field::Attributes => {
                            if attributes.is_some() {
                                return Err(Error::duplicate_field("attributes"));
                            }
                            let attr: Vec<(AttrId, EncodedVarbytes)> = map.next_value()?;
                            let mut a = Attributes::new();
                            attr.iter()
                                .try_for_each(|(id, attr)| -> Result<(), V::Error> {
                                    let i = *id;
                                    let v: Vec<u8> = (**attr).clone().to_inner();
                                    if a.insert(i, v).is_some() {
                                        return Err(Error::duplicate_field(
                                            "duplicate attribute id",
                                        ));
                                    }
                                    Ok(())
                                })?;
                            attributes = Some(a);
                        }
                    }
                }
                let codec = codec.ok_or_else(|| Error::missing_field("codec"))?;
                let message = message.ok_or_else(|| Error::missing_field("message"))?;
                let attributes = attributes.ok_or_else(|| Error::missing_field("attributes"))?;

                Ok(Self::Value {
                    codec,
                    message,
                    attributes,
                })
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_struct(ms::SIGIL.as_str(), FIELDS, MultisigVisitor)
        } else {
            // Use `deserialize_byte_buf` with a visitor that accepts both
            // borrowed and owned bytes. This works with `serde_test`
            // (BorrowedBytes), `serde_cbor` (borrowed), and `ciborium`
            // (owned). The previous `&'de [u8]` bound only worked with
            // deserializers that support borrowing from input.
            struct ByteBufVisitor;

            impl<'de> Visitor<'de> for ByteBufVisitor {
                type Value = Vec<u8>;

                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("byte buffer")
                }

                fn visit_borrowed_bytes<E: Error>(self, v: &'de [u8]) -> Result<Self::Value, E> {
                    Ok(v.to_vec())
                }

                fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                    Ok(v.to_vec())
                }

                fn visit_byte_buf<E: Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                    Ok(v)
                }
            }

            let b = deserializer.deserialize_byte_buf(ByteBufVisitor)?;
            Ok(Self::try_from(b.as_slice()).map_err(|e| Error::custom(e.to_string()))?)
        }
    }
}

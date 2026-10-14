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
                AttrId::try_from(c).map_err(E::custom)
            }

            // serde's default `visit_borrowed_str` and `visit_string`
            // forward here
            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                s.parse().map_err(E::custom)
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
                            attr.into_iter()
                                .try_for_each(|(i, attr)| -> Result<(), V::Error> {
                                    let v: Vec<u8> = attr.to_inner().to_inner();
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
            // `deserialize_byte_buf` with a visitor that accepts both borrowed
            // and owned bytes works with `serde_test` (BorrowedBytes),
            // `serde_cbor_2` (borrowed), and reader-based decoders (owned).
            // Both paths decode straight from the input bytes.
            struct ByteBufVisitor;

            impl Visitor<'_> for ByteBufVisitor {
                type Value = Multisig;

                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("byte buffer")
                }

                fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                    Multisig::try_from(v).map_err(E::custom)
                }

                fn visit_byte_buf<E: Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                    self.visit_bytes(v.as_slice())
                }
            }

            deserializer.deserialize_byte_buf(ByteBufVisitor)
        }
    }
}

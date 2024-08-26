use openssl::{pkey::Public, rsa::Rsa};
use serde::{
    de::{self, Visitor},
    ser::{Error, SerializeStruct},
    Deserialize, Serialize,
};

use crate::CryptError;

use super::{KeyFormat, PublicKey};

/// Stores the public key of Rsa.
#[derive(Debug)]
pub struct RsaPublicKey {
    key: Rsa<Public>,
}
impl PublicKey<Rsa<Public>> for RsaPublicKey {
    fn new(public_key: &[u8], key_format: KeyFormat) -> Result<Self, CryptError> {
        let key = match key_format {
            KeyFormat::DER => Rsa::public_key_from_der(public_key),
            KeyFormat::PEM => Rsa::public_key_from_pem(public_key),
        }
        .map_err(|e| CryptError::PublicKey(e))?;

        Ok(Self { key })
    }

    fn get_key(&self) -> &Rsa<Public> {
        &self.key
    }
}

impl Serialize for RsaPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("RsaPublicKey", 1)?;

        state.serialize_field(
            "key",
            &self.key.public_key_to_pem().map_err(|e| {
                S::Error::custom(format!(
                    "Could not serialize the public rsa key! Error: {}",
                    e
                ))
            })?,
        )?;

        state.end()
    }
}

impl<'de> Deserialize<'de> for RsaPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct RsaPublicKeyVisitor;

        impl<'de> Visitor<'de> for RsaPublicKeyVisitor {
            type Value = RsaPublicKey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a public rsa key")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut public_key: Option<Vec<u8>> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "key" => {
                            if public_key.is_some() {
                                return Err(de::Error::duplicate_field("key"));
                            };

                            public_key = Some(map.next_value()?)
                        }
                        _ => return Err(de::Error::unknown_field(&key, &["key"])),
                    };
                }

                let public_key = public_key.ok_or_else(|| de::Error::missing_field("key"))?;

                Ok(RsaPublicKey::new(&public_key, KeyFormat::PEM).map_err(|e| {
                    de::Error::custom(format!(
                        "Could not deserialize `RsaPublicKey`! Error: {}",
                        e
                    ))
                })?)
            }
        }

        deserializer.deserialize_struct("RsaPublicKey", &["key"], RsaPublicKeyVisitor)
    }
}

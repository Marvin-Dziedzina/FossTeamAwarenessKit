use openssl::pkey::{PKey, Public};
use serde::{
    de::{self, Visitor},
    ser::{Error, SerializeStruct},
    Deserialize, Serialize,
};

use crate::CryptError;

use super::{KeyFormat, PublicKey};

/// Stores the PKey.
#[derive(Debug)]
pub struct SignPublicKey {
    key: PKey<Public>,
}
impl PublicKey<PKey<Public>> for SignPublicKey {
    fn new(public_key: &[u8], key_format: KeyFormat) -> Result<Self, CryptError>
    where
        Self: Sized,
    {
        let key = match key_format {
            KeyFormat::DER => PKey::public_key_from_der(public_key),
            KeyFormat::PEM => PKey::public_key_from_pem(public_key),
        }
        .map_err(|e| CryptError::PublicKey(e))?;

        Ok(Self { key })
    }

    fn get_key(&self) -> &PKey<Public> {
        &self.key
    }
}

impl Serialize for SignPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("SignPublicKey", 1)?;

        state.serialize_field(
            "key",
            &self.key.public_key_to_pem().map_err(|e| {
                S::Error::custom(format!("Could not serialize SignPublicKey! Error: {}", e))
            })?,
        )?;

        state.end()
    }
}

impl<'de> Deserialize<'de> for SignPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SignPublicKeyVisitor;

        impl<'de> Visitor<'de> for SignPublicKeyVisitor {
            type Value = SignPublicKey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a public rsa sign key")
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

                            public_key = Some(map.next_value()?);
                        }
                        _ => return Err(de::Error::unknown_field(&key, &["key"])),
                    }
                }

                let public_key = public_key.ok_or_else(|| de::Error::missing_field("key"))?;

                Ok(
                    SignPublicKey::new(&public_key, KeyFormat::PEM).map_err(|e| {
                        de::Error::custom(format!(
                            "Could not deserialize `SignPublicKey`! Error: {}",
                            e
                        ))
                    })?,
                )
            }
        }

        deserializer.deserialize_struct("SignPublicKey", &["key"], SignPublicKeyVisitor)
    }
}

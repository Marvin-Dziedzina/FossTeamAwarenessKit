use openssl::{
    pkey::{PKey, Public},
    rsa::Rsa,
};
use serde::{
    de::{self, Visitor},
    ser::{Error, SerializeStruct},
    Deserialize, Serialize,
};

use crate::CryptError;

/// Stores the rsa public key and the sign public key.
#[derive(Debug, Clone)]
pub struct PublicKey {
    rsa_key: Rsa<Public>,
    sign_key: PKey<Public>,
}
impl PublicKey {
    /// Create new instance of `PublicKey` from public keys.
    pub fn new(
        rsa_public_key: &[u8],
        rsa_public_key_format: KeyFormat,
        sign_public_key: &[u8],
        sign_public_key_format: KeyFormat,
    ) -> Result<Self, CryptError> {
        let rsa_key = match rsa_public_key_format {
            KeyFormat::DER => Rsa::public_key_from_der(rsa_public_key),
            KeyFormat::PEM => Rsa::public_key_from_pem(rsa_public_key),
        }
        .map_err(|e| CryptError::PublicKey(e))?;

        let sign_key = match sign_public_key_format {
            KeyFormat::DER => PKey::public_key_from_der(sign_public_key),
            KeyFormat::PEM => PKey::public_key_from_pem(sign_public_key),
        }
        .map_err(|e| CryptError::PublicKey(e))?;

        Ok(Self { rsa_key, sign_key })
    }

    pub fn get_rsa_key(&self) -> &Rsa<Public> {
        &self.rsa_key
    }

    pub fn get_rsa_key_der(&self) -> Result<Vec<u8>, CryptError> {
        Ok(self
            .rsa_key
            .public_key_to_der()
            .map_err(|e| CryptError::PublicKey(e))?)
    }

    pub fn get_rsa_key_pem(&self) -> Result<Vec<u8>, CryptError> {
        Ok(self
            .rsa_key
            .public_key_to_pem()
            .map_err(|e| CryptError::PublicKey(e))?)
    }

    pub fn get_sign_key(&self) -> &PKey<Public> {
        &self.sign_key
    }

    pub fn get_sign_key_der(&self) -> Result<Vec<u8>, CryptError> {
        Ok(self
            .sign_key
            .public_key_to_der()
            .map_err(|e| CryptError::PublicKey(e))?)
    }

    pub fn get_sign_key_pem(&self) -> Result<Vec<u8>, CryptError> {
        Ok(self
            .sign_key
            .public_key_to_pem()
            .map_err(|e| CryptError::PublicKey(e))?)
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("PublicKey", 2)?;

        let rsa_public_key = &self.rsa_key.public_key_to_pem().map_err(|e| {
            S::Error::custom(format!(
                "Could not serialize `rsa_key` from `PublicKey`! Error: {}",
                e
            ))
        })?;
        let sign_public_key = &self.sign_key.public_key_to_pem().map_err(|e| {
            S::Error::custom(format!(
                "Could not serialize `sign_key` from `PublicKey`! Error: {}",
                e
            ))
        })?;

        state.serialize_field("rsa_public_key", &rsa_public_key)?;
        state.serialize_field("sign_public_key", &sign_public_key)?;

        state.end()
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PublicKeyVisitor;

        impl<'de> Visitor<'de> for PublicKeyVisitor {
            type Value = PublicKey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a rsa_public_key and a sign_public_key")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut rsa_public_key: Option<Vec<u8>> = None;
                let mut sign_public_key: Option<Vec<u8>> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "rsa_public_key" => {
                            if rsa_public_key.is_some() {
                                return Err(de::Error::duplicate_field("rsa_public_key"));
                            };

                            rsa_public_key = Some(map.next_value()?);
                        }
                        "sign_public_key" => {
                            if sign_public_key.is_some() {
                                return Err(de::Error::duplicate_field("sign_public_key"));
                            };

                            sign_public_key = Some(map.next_value()?)
                        }
                        _ => {
                            return Err(de::Error::unknown_field(
                                &key,
                                &["rsa_public_key", "sign_public_key"],
                            ))
                        }
                    }
                }

                let rsa_public_key =
                    rsa_public_key.ok_or_else(|| de::Error::missing_field("rsa_public_key"))?;
                let sign_public_key =
                    sign_public_key.ok_or_else(|| de::Error::missing_field("sign_public_key"))?;

                Ok(PublicKey::new(
                    &rsa_public_key,
                    KeyFormat::PEM,
                    &sign_public_key,
                    KeyFormat::PEM,
                )
                .map_err(|e| de::Error::custom(format!("{}", e)))?)
            }
        }

        deserializer.deserialize_struct(
            "PublicKey",
            &["rsa_public_key", "sign_public_key"],
            PublicKeyVisitor,
        )
    }
}

/// Common supported key formats
#[derive(Debug, Serialize, Deserialize)]
pub enum KeyFormat {
    PEM,
    DER,
}

#[cfg(test)]
mod public_key_tests {
    use crate::*;

    #[test]
    fn public_key_serde() {
        let public_key = RSA::new(2048).unwrap().get_public_keys().unwrap();

        let json = serde_json::to_string(&public_key).unwrap();

        let _: PublicKey = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn get_public_key() {
        get_pub_key().unwrap();
    }

    #[test]
    fn get_rsa_key_der() {
        let public_key = get_pub_key().unwrap();
        public_key.get_rsa_key_der().unwrap();
    }

    #[test]
    fn get_rsa_key_pem() {
        let public_key = get_pub_key().unwrap();
        public_key.get_rsa_key_pem().unwrap();
    }

    #[test]
    fn get_sign_key_der() {
        let public_key = get_pub_key().unwrap();
        public_key.get_sign_key_der().unwrap();
    }

    #[test]
    fn get_sign_key_pem() {
        let public_key = get_pub_key().unwrap();
        public_key.get_sign_key_pem().unwrap();
    }

    fn get_pub_key() -> Result<PublicKey, CryptError> {
        let rsa = RSA::new(2048)?;
        rsa.get_public_keys()
    }
}

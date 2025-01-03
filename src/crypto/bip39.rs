use bip39;

use crate::crypto::Result;
use shush_rs::{ExposeSecret, SecretString};

pub(crate) use bip39::Error;
use strum_macros::EnumIter;

pub fn generate_recovery_phrase(language: Language, password: &SecretString) -> Result<String> {
    let recovery_phrase = bip39::Mnemonic::from_entropy_in(language.into(), &password.expose_secret().as_bytes())?;

    Ok(recovery_phrase.to_string())
}

// Can create a struct here.
pub fn mnemonic_to_password(mnemonic: &SecretString) -> Result<SecretString> {
      let parsed_data = bip39::Mnemonic::parse_normalized(&mnemonic.expose_secret())?;

      Ok(SecretString::from(Box::new(parsed_data.to_string())))
}

// Avoid depending on the library directly.
#[derive(Copy, Clone, EnumIter)]
pub enum Language {

    English,
    // #[cfg(feature = "chinese-simplified")]
    SimplifiedChinese,
    // #[cfg(feature = "chinese-traditional")]
    TraditionalChinese,
    // #[cfg(feature = "czech")]
    Czech,
    // #[cfg(feature = "french")]
    French,
    // #[cfg(feature = "italian")]
    Italian,
    // #[cfg(feature = "japanese")]
    Japanese,
    // #[cfg(feature = "korean")]
    Korean,
    // #[cfg(feature = "portuguese")]
    Portuguese,
    // #[cfg(feature = "spanish")]
    Spanish,
}

impl From<Language> for bip39::Language {
    fn from(value: Language) -> Self {
        match value {
            Language::English => bip39::Language::English,
            // #[cfg(feature = "chinese-simplified")]
            Language::SimplifiedChinese => bip39::Language::SimplifiedChinese,
            // #[cfg(feature = "chinese-traditional")]
            Language::TraditionalChinese => bip39::Language::TraditionalChinese,
            // #[cfg(feature = "czech")]
            Language::Czech => bip39::Language::Czech,
            // #[cfg(feature = "french")]
            Language::French => bip39::Language::French,
            // #[cfg(feature = "italian")]
            Language::Italian => bip39::Language::Italian,
            // #[cfg(feature = "japanese")]
            Language::Japanese => bip39::Language::Japanese,
            // #[cfg(feature = "korean")]
            Language::Korean => bip39::Language::Korean,
            // #[cfg(feature = "portuguese")]
            Language::Portuguese => bip39::Language::Portuguese,
            // #[cfg(feature = "spanish")]
            Language::Spanish => bip39::Language::Spanish,
        }
    }
}

impl From<bip39::Language> for Language {
    fn from(value: bip39::Language) -> Self {
        match value {
            bip39::Language::English => Language::English,
            // #[cfg(feature = "chinese-simplified")]
            bip39::Language::SimplifiedChinese => Language::SimplifiedChinese,
            // #[cfg(feature = "chinese-traditional")]
            bip39::Language::TraditionalChinese => Language::TraditionalChinese,
            // #[cfg(feature = "czech")]
            bip39::Language::Czech => Language::Czech,
            // #[cfg(feature = "french")]
            bip39::Language::French => Language::French,
            // #[cfg(feature = "italian")]
            bip39::Language::Italian => Language::Italian,
            // #[cfg(feature = "japanese")]
            bip39::Language::Japanese => Language::Japanese,
            // #[cfg(feature = "korean")]
            bip39::Language::Korean => Language::Korean,
            // #[cfg(feature = "portuguese")]
            bip39::Language::Portuguese => Language::Portuguese,
            // #[cfg(feature = "spanish")]
            bip39::Language::Spanish => Language::Spanish,
        }
    }
}

impl Default for Language {
    fn default() -> Self {
       Language::English
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use argon2::password_hash::rand_core::RngCore;
    use super::*;
    use shush_rs::SecretVec;
    use strum::IntoEnumIterator;

    #[test]
    fn init_recovery_phrase(){
        let secret_str = SecretString::from_str("This is a test string").unwrap();
        for lang in Language::iter() {

            let recovery_phrase = generate_recovery_phrase(lang, &secret_str).unwrap();
            let recovery_phrase = SecretString::new(Box::new(recovery_phrase));
            let mnemonic = mnemonic_to_password(&recovery_phrase).unwrap();
            // add this assert.
            // assert_eq!(entropy, mnemonic.expose_secret().to_string());
        }


    }
}

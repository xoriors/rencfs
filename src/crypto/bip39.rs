use bip39;

use crate::crypto::Result;
use shush_rs::{ExposeSecret, SecretVec};

pub(crate) use bip39::Error;
use strum_macros::EnumIter;

pub(crate) fn generate_recovery_phrase(language: Language, key:&SecretVec<u8>) -> Result<String> {
    let entropy = key.expose_secret();
    let recovery_phrase = bip39::Mnemonic::from_entropy_in(language.into(), &entropy)?;

    Ok(recovery_phrase.to_string())
}

pub(crate) fn mnemonic_to_entropy(mnemonic: &str) -> Result<Vec<u8>>{
      let parsed_data = bip39::Mnemonic::parse_normalized(mnemonic)?;
      Ok(parsed_data.to_entropy())
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

impl Default for Language {
    fn default() -> Self {
       Language::English
    }
}

#[cfg(test)]
mod tests {
    use argon2::password_hash::rand_core::RngCore;
    use crate::crypto::bip39::{generate_recovery_phrase, mnemonic_to_entropy, Language};
    use shush_rs::SecretVec;
    use strum::IntoEnumIterator;

    #[test]
    fn init_recovery_phrase(){
        let mut entropy = vec![0; 16];
        crate::crypto::create_rng().fill_bytes(&mut entropy);
        let secret_vec = SecretVec::new(Box::new(entropy.clone()));
        for lang in Language::iter() {

            let recovery_phrase = generate_recovery_phrase(lang, &secret_vec).unwrap();
            let derived_entropy = mnemonic_to_entropy(&recovery_phrase).unwrap();
            assert_eq!(entropy, derived_entropy);
        }


    }
}

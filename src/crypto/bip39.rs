pub use bip39;
use shush_rs::{ExposeSecret, SecretVec};
use crate::encryptedfs::FsError;
use crate::crypto::Result;

pub(crate) use bip39::Error;

pub(crate) fn generate_recovery_phrase(language: Language, key:&SecretVec<u8>) -> Result<String> {
    let entropy = key.expose_secret();
    let recovery_phrase = bip39::Mnemonic::from_entropy_in(language.into(), &entropy)?;

    Ok(recovery_phrase.to_string())
}

// Avoid depending on the library directly.
#[derive(Copy, Clone)]
pub enum Language {

    English,
    // #[cfg(feature = "chinese-simplified")]
    /// The Simplified Chinese language.
    SimplifiedChinese,
    // #[cfg(feature = "chinese-traditional")]
    /// The Traditional Chinese language.
    TraditionalChinese,
    // #[cfg(feature = "czech")]
    /// The Czech language.
    Czech,
    // #[cfg(feature = "french")]
    /// The French language.
    French,
    // #[cfg(feature = "italian")]
    /// The Italian language.
    Italian,
    // #[cfg(feature = "japanese")]
    /// The Japanese language.
    Japanese,
    // #[cfg(feature = "korean")]
    /// The Korean language.
    Korean,
    // #[cfg(feature = "portuguese")]
    /// The Portuguese language.
    Portuguese,
    // #[cfg(feature = "spanish")]
    /// The Spanish language.
    Spanish,
}

impl From<Language> for bip39::Language {
    fn from(value: Language) -> Self {
        match value {
            Language::English => bip39::Language::English,
            Language::SimplifiedChinese => bip39::Language::SimplifiedChinese,
            Language::TraditionalChinese => bip39::Language::TraditionalChinese,
            Language::Czech => bip39::Language::Czech,
            Language::French => bip39::Language::French,
            Language::Italian => bip39::Language::Italian,
            Language::Japanese => bip39::Language::Japanese,
            Language::Korean => bip39::Language::Korean,
            Language::Portuguese => bip39::Language::Portuguese,
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
    use shush_rs::SecretVec;
    use crate::crypto::bip39::{Language, generate_recovery_phrase};
    use crate::crypto::bip39::Language::{Czech, English, TraditionalChinese};

    #[test]
    fn init_recovery_phrase(){
        let entropy = [3u8;32];
        let secret_vec = SecretVec::new(Box::new(entropy.to_vec()));
        let recovery_phrase = generate_recovery_phrase(TraditionalChinese, &secret_vec);
        assert_eq!(24, recovery_phrase.split(" ").count());
        println!("{:?}", recovery_phrase);
    }
}

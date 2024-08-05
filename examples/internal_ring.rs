#![cfg_attr(not(debug_assertions), deny(warnings))]
#![feature(test)]
// #![feature(error_generic_member_access)]
#![feature(seek_stream_len)]
#![feature(const_refs_to_cell)]
#![doc(html_playground_url = "https://play.rust-lang.org")]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![deny(clippy::nursery)]
#![deny(clippy::cargo)]
// #![deny(missing_docs)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::missing_errors_doc)]
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};

fn main() {
    let key = [42; 32];
    let nonce_data = [124; 12]; // Just an example
    let mut data = b"hello, this is my secret message".to_vec();

    let key = UnboundKey::new(&CHACHA20_POLY1305, &key).unwrap();
    let key = LessSafeKey::new(key);
    println!("{data:?}");

    // encoding
    let nonce = Nonce::assume_unique_for_key(nonce_data);
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut data)
        .unwrap();
    println!("{data:?}");

    // decoding
    let nonce = Nonce::assume_unique_for_key(nonce_data);
    let data = key.open_in_place(nonce, Aad::empty(), &mut data).unwrap();
    println!("{data:?}");
}

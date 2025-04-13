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

fn main() {
    use pbkdf2::pbkdf2_hmac_array;
    use sha2::Sha256;

    let password = b"password";
    let salt = b"salt-42";
// number of iterations
    let n = 600_000;
// Expected value of generated key

    // let mut key1 = [0u8; 20];
    // pbkdf2_hmac::<Sha256>(password, salt, n, &mut key1);
    // println!("{:?}", key1);

    let key2 = pbkdf2_hmac_array::<Sha256, 32>(password, salt, n);
    println!("{:?}", key2);
}
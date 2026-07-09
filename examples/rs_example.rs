use rencfs::crypto::rs::RsEncoder;

fn main() {
    let encoder = RsEncoder::new(3, 2);
    let data = b"hello, this is my message";

    println!("Original: {}", String::from_utf8_lossy(data));

    let shards = encoder.encode(data).expect("encode failed");
    println!("Created {} shards", shards.len());

    let mut shards_opt: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
    shards_opt[0] = None; // drop one data shard
    shards_opt[4] = None; // drop one parity shard

    println!("Simulated missing shards at indexes 0 and 4");

    let recovered = encoder
        .reconstruct(&mut shards_opt)
        .expect("reconstruct failed");

    println!("Recovered: {}", String::from_utf8_lossy(&recovered));
}

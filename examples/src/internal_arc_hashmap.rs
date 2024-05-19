use rencfs::arc_hashmap::ArcHashMap;

fn main() {
    let mut m = ArcHashMap::default();
    {
        let v = m.insert(1, 2);
        println!("size {}", m.len());
        m.insert(2, 3);
        println!("size {}", m.len());
        let v = m.get_or_insert_with(3, || 4);
        println!("size {}", m.len());
    }
    println!("size {}", m.len());
}

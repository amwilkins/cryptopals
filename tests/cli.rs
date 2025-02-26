use set_1::hamming_distance;

#[test]
fn test_hamming_distance() {
    let s1 = "this is a test";
    let s2 = "wokka wokka!!!";
    let s1_byte = s1.as_bytes();
    let s2_byte = s2.as_bytes();
    let dist = hamming_distance(s1_byte, s2_byte);
    println!("{}", dist);
    assert_eq!(dist, 37)
}

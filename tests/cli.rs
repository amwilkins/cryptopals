use set_1::hamming_distance;

#[test]
fn test_hamming_distance() {
    let s1 = "this is a test";
    let s2 = "wokka wokka!!!";
    let dist = hamming_distance(s1, s2);
    println!("{}", dist);
    assert_eq!(dist, 37)
}

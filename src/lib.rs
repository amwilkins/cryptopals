use base64::{engine::general_purpose::STANDARD, Engine as _};
use hex;
use std::str;

pub fn hex_to_b64(hex_string: &str) -> String {
    let decoded_bytes = hex_to_byte(hex_string);
    STANDARD.encode(decoded_bytes)
}

// formats -> bytes
pub fn hex_to_byte(hex_string: &str) -> Vec<u8> {
    let bytes = hex::decode(hex_string).unwrap();
    bytes
}

pub fn b64_to_byte(b64: &str) -> Vec<u8> {
    STANDARD.decode(b64).unwrap()
}

pub fn string_to_byte(string: &str) -> Vec<u8> {
    let bytes = string.as_bytes().to_vec();
    return bytes;
}

pub fn xor_against(byte_string: &Vec<u8>, byte_key: u8) -> Vec<u8> {
    let mut decoded_bytes: Vec<u8> = Vec::new();
    for char in byte_string {
        let decoded_byte = char ^ byte_key;
        decoded_bytes.push(decoded_byte);
    }
    return decoded_bytes;
}

// https://crypto.stackexchange.com/questions/30209/developing-algorithm-for-detecting-plain-text-via-frequency-analysis
const LETTER_FREQ: [f64; 27] = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, // A-G
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, // H-N
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, // O-U
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074, 0.19181, // V-Z & space char
];

pub fn calc_letter_freq_score(string: &str) -> f64 {
    let mut counts = vec![0_u32; 27];
    let mut score: f64 = 0_f64;

    string.chars().for_each(|c| match c {
        'a'..='z' => {
            counts[c as usize - 97] += 1;
        }
        'A'..='Z' => {
            counts[c as usize - 65] += 1;
        }
        ' ' => counts[26] += 1,
        _ => {}
    });

    for i in 0..27 {
        score += (counts[i] as f64) * LETTER_FREQ[i];
    }
    score
}

pub fn detect_single_xor(string: &str) -> (String, f64) {
    //let byte_string = string.as_bytes().to_vec();
    let mut best_score = f64::MIN;
    let mut key_byte: u16;
    let mut best_match = String::new();
    for letter in 0..=255 {
        key_byte = letter as u16;
        let byte_decoded: Vec<u16> = hex::decode(string)
            .unwrap()
            .iter()
            .map(|&byte| (byte as u16) ^ key_byte)
            .collect();
        let string_decoded = String::from_utf16(&byte_decoded).unwrap();
        let score = calc_letter_freq_score(&string_decoded);

        if score > best_score {
            best_score = score;
            best_match = String::from(string_decoded);
        }
    }
    (best_match, best_score)
}

pub fn repeating_key_xor(string: &str, key: &str) -> String {
    let key_expanded: String = key.chars().cycle().take(string.len()).collect::<String>();
    let byte_key = key_expanded.as_bytes();
    let byte_string = string.as_bytes();
    let string_encoded: Vec<u8> = byte_string
        .iter()
        .zip(byte_key.iter())
        .map(|(&string_byte, &key_byte)| string_byte ^ key_byte)
        .collect();
    hex::encode(string_encoded)
}

pub fn hamming_distance(s1: &str, s2: &str) -> u64 {
    assert_eq!(s1.len(), s2.len());
    let s1_byte = s1.as_bytes();
    let s2_byte = s2.as_bytes();
    s1_byte
        .iter()
        .zip(s2_byte)
        .fold(0, |a, (b, c)| a + (*b ^ *c).count_ones() as u64)
}

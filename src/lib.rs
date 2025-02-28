use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hex;
use rand::{random_range, RngCore};
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

pub fn detect_single_xor(string_bytes: &[u8]) -> (u8, f64, String) {
    //let byte_string = string.as_bytes().to_vec();
    let mut best_score = f64::MIN;
    let mut best_match = String::new();
    let mut best_key: u8 = 0;
    for letter in 0..=255 {
        let byte_decoded: Vec<u8> = string_bytes.iter().map(|&byte| byte ^ letter).collect();
        let string_decoded = String::from_utf8_lossy(&byte_decoded);
        let score = calc_letter_freq_score(&string_decoded);

        if score > best_score {
            best_score = score;
            best_match = String::from(string_decoded);
            best_key = letter;
        }
    }
    (best_key, best_score, best_match)
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

pub fn hamming_distance(s1: &[u8], s2: &[u8]) -> u64 {
    assert_eq!(s1.len(), s2.len());
    s1.iter()
        .zip(s2)
        .fold(0, |a, (b, c)| a + (*b ^ *c).count_ones() as u64)
}

pub fn test_key_lengths(key_length: usize, byte_string: &[u8]) -> f64 {
    let len = byte_string.len();
    let mut i: usize = 0;
    let mut total_dist = 0;
    let mut chunk1;
    let mut chunk2;

    loop {
        if i * 2 * key_length >= len {
            break;
        }

        // First and second chunk of key_length bytes
        chunk1 = &byte_string[i * key_length..(i + 1) * key_length];
        chunk2 = &byte_string[(i + 1) * key_length..(i + 2) * key_length];

        total_dist += hamming_distance(chunk1, chunk2) / (key_length as u64);
        i += 1;
    }
    (total_dist as f64) / (i as f64 + 1.0)
}

// XOR combine
pub fn xor_encode(block1: &[u8], block2: &[u8]) -> Vec<u8> {
    assert_eq!(block1.len(), block2.len());
    let mut output = Vec::new();
    for (a, b) in block1.iter().zip(block2.iter()) {
        output.push(a ^ b);
    }

    output
}
/// Encrypts a single block of ciphertext using AES-128.
pub fn aes128_encrypt_block(block: &[u8], key: &[u8]) -> Vec<u8> {
    assert_eq!(block.len(), 16);
    assert_eq!(key.len(), 16);
    let cipher = aes::Aes128::new_from_slice(key).unwrap();
    let mut block = *GenericArray::from_slice(block);
    cipher.encrypt_block(&mut block);
    block.to_vec()
}

/// Decrypts a single block of ciphertext using AES-128.
pub fn aes128_decrypt_block(block: &[u8], key: &[u8]) -> Vec<u8> {
    assert_eq!(block.len(), 16);
    assert_eq!(key.len(), 16);
    let cipher = aes::Aes128::new_from_slice(key).unwrap();
    let mut block = *GenericArray::from_slice(block);
    cipher.decrypt_block(&mut block);
    block.to_vec()
}

pub fn aes128_ecb_encrypt(input: &[u8], key: &[u8]) -> Vec<u8> {
    assert_eq!(input.len() % 16, 0);
    input
        .chunks(16)
        .flat_map(|chunk| aes128_encrypt_block(chunk, key))
        .collect()
}

pub fn aes128_ecb_decrypt(input: &[u8], key: &[u8]) -> Vec<u8> {
    assert_eq!(input.len() % 16, 0);
    input
        .chunks(16)
        .flat_map(|chunk| aes128_decrypt_block(chunk, key))
        .collect()
}

pub fn pad_block_size(input: &[u8], block_size: usize) -> Vec<u8> {
    assert!(
        block_size < 128,
        "Block size limited to 128, please use smaller block size."
    );
    let mut output = input.to_vec();
    let pad_size = block_size - (input.len() % block_size);
    output.append(&mut vec![pad_size as u8; pad_size]);

    output
}
pub fn cbc_encrypt(input: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    assert_eq!(input.len() % 16, 0);
    let mut previous_block = iv.to_vec();
    let mut output = Vec::new();
    for chunk in input.chunks(16) {
        let mut block = xor_encode(previous_block.as_slice(), chunk);
        block = aes128_ecb_encrypt(block.as_slice(), key);
        output.append(&mut block.clone());
        previous_block = block;
    }
    output
}

pub fn cbc_decrypt(input: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    assert_eq!(input.len() % 16, 0);
    let mut previous_block = iv.to_vec();
    let mut output = Vec::new();
    for chunk in input.chunks(16) {
        let block = aes128_ecb_decrypt(chunk, key);
        let mut block = xor_encode(previous_block.as_slice(), block.as_slice());
        output.append(&mut block);
        previous_block = chunk.to_vec();
    }
    output
}

pub fn generate_random_aes_key() -> Vec<u8> {
    let key = rand::random_iter::<u8>().take(16).collect();
    key
}

pub fn encryption_oracle(input: &str) -> Vec<u8> {
    let mut rng = rand::rng();

    // add random bytes before and after message
    let prefix = rand::random_iter::<u8>()
        .take(random_range(5..=10))
        .collect();
    let suffix = rand::random_iter::<u8>()
        .take(random_range(5..=10))
        .collect();
    let judas_marker = vec![0; 64];
    let padded_input_bytes = pad_block_size(
        [prefix, judas_marker, input.as_bytes().to_vec(), suffix]
            .concat()
            .as_slice(),
        16,
    );

    let cbc_flag = rand::random_bool(0.5);
    let key = generate_random_aes_key();
    let mut _ciphertext = Vec::new();

    // encrypt based on cbc_flag
    if cbc_flag {
        let mut iv = [0u8; 16];
        rng.fill_bytes(&mut iv);
        _ciphertext = cbc_encrypt(&padded_input_bytes, &key, &iv)
    } else {
        _ciphertext = aes128_ecb_encrypt(&padded_input_bytes, &key)
    }
    _ciphertext
}

pub fn detect_block_cipher_mode(f: fn(&str) -> Vec<u8>) -> (String, Vec<u8>) {
    let input = "x".repeat(64);
    let ciphertext = f(input.as_str());
    let mut prev_block = vec![0; 16];

    // look for repeated blocks
    for block in ciphertext.chunks(16) {
        if block == prev_block {
            return ("ECB".to_string(), ciphertext);
        } else {
            prev_block = block.to_vec();
        }
    }
    return ("CBC".to_string(), ciphertext);
}

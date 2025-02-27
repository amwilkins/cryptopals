use cryptopals::*;
use hex;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader};

fn s1c1() {
    /* S01C01
      The string:
    49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
    Should produce:
    SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
    So go ahead and make that happen. You'll need to use this code for the rest of the exercises.
    */
    println!("\nS01C01 Converting hex into base64:");
    let hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let b64_string = cryptopals::hex_to_b64(hex_string);
    println!("{}", b64_string);
}
fn s1c2() {
    /* S01C02
    Write a function that takes two equal-length buffers and produces their XOR combination.
    If your function works properly, then when you feed it the string:
    1c0111001f010100061a024b53535009181c
    ... after hex decoding, and when XOR'd against:
    686974207468652062756c6c277320657965
    ... should produce:
    746865206b696420646f6e277420706c6179
    */
    println!("\nS01C02 XOR of 2 equal length buffers:");
    let s1 = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
    let s2 = hex::decode("686974207468652062756c6c277320657965").unwrap();
    let xor_string: Vec<u8> = s1.iter().zip(s2.iter()).map(|(&b1, &b2)| b1 ^ b2).collect();
    let output = hex::encode(xor_string);
    println!("{:?}", output);
}

fn s1c3() {
    /* S01C03
    The hex encoded string:
    1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
    ... has been XOR'd against a single character. Find the key, decrypt the message.
    You can do this by hand. But don't: write code to do it for you.
    How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.
    */
    println!("\nS01C03 Single byte XOR cipher");
    let s1c3_hex_string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let s1c3_byte_string = hex::decode(s1c3_hex_string).unwrap();
    let mut s1c3_message = String::new();
    let mut s1c3_best_score = f64::MIN;
    let mut key_byte: u8 = 0;
    for letter in 0..=255 {
        key_byte = letter as u8;
        let s1c3_byte_decoded: Vec<u8> = s1c3_byte_string
            .iter()
            .map(|&byte| byte ^ key_byte)
            .collect();
        let s1c3_string_decoded = String::from_utf8_lossy(&s1c3_byte_decoded);
        let score = calc_letter_freq_score(&s1c3_string_decoded);

        if score > s1c3_best_score {
            s1c3_best_score = score;
            s1c3_message = String::from(s1c3_string_decoded);
        }
    }
    println!("Letter: {}, Message: {}", key_byte as char, s1c3_message);
}
fn s1c4() {
    println!("\nS01C04 Detect single-character XOR");
    /* S01C04
    One of the 60-character strings in this file[https://cryptopals.com/static/challenge-data/4.txt] has been encrypted by single-character XOR.
    Find it.
    */
    let file = File::open("data/4.txt").expect("Error reading file.");
    let lines = BufReader::new(file).lines();

    let mut s1c4_best_score = f64::MIN;
    let mut s1c4_best_match = String::new();
    let mut s1c4_best_key = u8::MIN;

    for line in lines {
        let line = line.unwrap();
        let line_bytes = hex::decode(line).unwrap();
        let s1c4_result = detect_single_xor(&line_bytes);
        let s1c4_message = s1c4_result.2;
        let s1c4_score = s1c4_result.1;
        let s1c4_key = s1c4_result.0;
        if s1c4_score > s1c4_best_score {
            s1c4_best_score = s1c4_score;
            s1c4_best_match = String::from(s1c4_message);
            s1c4_best_key = s1c4_key;
        }
    }
    println!(
        "Best key: {}, Best Score: {}, Message: {}",
        s1c4_best_key, s1c4_best_score, s1c4_best_match
    );
}
fn s1c5() {
    println!("\nS01C05 Implement repeating-key XOR");
    /*
    Here is the opening stanza of an important work of the English language:
    Burning 'em, if you ain't quick and nimble
    I go crazy when I hear a cymbal
    Encrypt it, under the key "ICE", using repeating-key XOR.
    In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.
    It should come out to:
    0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
    a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
    Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this.
    */
    let s1c5_string: &str =
        "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let s1c5_key: &str = "ICE";
    let s1c5_encoded = cryptopals::repeating_key_xor(s1c5_string, s1c5_key);
    println!("{}", s1c5_encoded)
}
fn s1c6() {
    println!("\nS01C06 Break repeating-key XOR");
    /*
    There's a file here. It's been base64'd after being encrypted with repeating-key XOR.
    Decrypt it.
    Here's how:
        1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
        2. Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:
        this is a test
        and
        wokka wokka!!!
        is 37. Make sure your code agrees before you proceed.
        3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
        4. The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
        5. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
        6. Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
        7. Solve each block as if it was single-character XOR. You already have code to do this.
        8. For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.
                                                L
    This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But more people "know how" to break it than can actually break it, and a similar technique breaks something much more important.
    */

    let s1c6_file = fs::read_to_string("data/6.txt")
        .and_then(|text| Ok(text.replace("\n", "")))
        .expect("Error reading file.");
    let s1c6_file_bytes = cryptopals::b64_to_byte(&s1c6_file);
    let mut s1c6_key_length_dists: Vec<(usize, f64)> = Vec::new();

    for s1c6_key_size in 2..=40 {
        let s1c6_dist = cryptopals::test_key_lengths(s1c6_key_size, &s1c6_file_bytes);
        s1c6_key_length_dists.push((s1c6_key_size, s1c6_dist));
    }
    s1c6_key_length_dists.sort_by(|x, y| y.1.partial_cmp(&x.1).unwrap());
    let s1c6_key_size = s1c6_key_length_dists.pop().and_then(|x| Some(x.0)).unwrap();

    let mut index;
    let mut s1c6_byte_block: Vec<u8> = Vec::new();
    let mut s1c6_key_bytes: Vec<u8> = Vec::new();

    for i in 0..s1c6_key_size {
        index = i;
        s1c6_byte_block.clear();
        // collect byte from multiples of s1c6_key_size
        while index < s1c6_file_bytes.len() {
            s1c6_byte_block.push(s1c6_file_bytes[index]);
            index += s1c6_key_size
        }
        let s1c6_key_byte = cryptopals::detect_single_xor(&s1c6_byte_block).0;
        s1c6_key_bytes.push(s1c6_key_byte)
    }
    let s1c6_key: String = s1c6_key_bytes.iter().map(|&byte| byte as char).collect();
    println!("{}", s1c6_key);
}

fn s1c7() {
    println!("\nS01C07 Break repeating-key XOR");
    /*
    The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key
    "YELLOW SUBMARINE".
    (case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).
    Decrypt it. You know the key, after all.
    Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
    */

    let s1c7_file = fs::read_to_string("data/7.txt")
        .and_then(|text| Ok(text.replace("\n", "")))
        .expect("Error reading file.");
    let s1c7_file_bytes = cryptopals::b64_to_byte(&s1c7_file);
    let s1c7_key_bytes = "YELLOW SUBMARINE".as_bytes();

    let _s1c7_message = String::from_utf8(aes128_ecb_decrypt(
        s1c7_file_bytes.as_slice(),
        s1c7_key_bytes,
    ))
    .unwrap();
    //println!("{}", s1c7_message);
}
fn s1c8() {
    println!("\nS01C08 Detect AES in ECB mode");
    /*
     In this file are a bunch of hex-encoded ciphertexts.
    One of them has been encrypted with ECB.
    Detect it.
    Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
         */
    let s1c8_file = fs::read_to_string("data/8.txt")
        .unwrap()
        .lines()
        .map(|lines| hex::decode(lines).unwrap())
        .collect::<Vec<_>>();

    let mut s1c8_best_score = std::f64::MAX;
    let mut s1c8_best_line = 0;

    for (i, line) in s1c8_file.iter().enumerate() {
        let mut s1c8_line_score = 0.0;

        for (ci1, chunk1) in line.chunks(16).enumerate() {
            for (ci2, chunk2) in line.chunks(16).enumerate() {
                if ci1 == ci2 {
                    continue;
                }

                s1c8_line_score += cryptopals::hamming_distance(chunk1, chunk2) as f64 / 16.0;
            }
        }
        if s1c8_line_score < s1c8_best_score {
            s1c8_best_score = s1c8_line_score;
            s1c8_best_line = i;
        }
    }
    println!("Detected line {}", s1c8_best_line);
    assert_eq!(s1c8_best_line, 132)
}

pub fn run() {
    s1c1();
    s1c2();
    s1c3();
    s1c4();
    s1c5();
    s1c6();
    s1c7();
    s1c8();
}

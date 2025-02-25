use clap::Parser;
use hex;
use set_1;
use set_1::{calc_letter_freq_score, detect_single_xor};
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Parser)]
struct Cli {
    hex_string: String,
}

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
    let b64_string = set_1::hex_to_b64(hex_string);
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
    let file = File::open("src/4.txt").expect("Error reading file.");
    let lines = BufReader::new(file).lines();

    let mut s1c4_best_score = f64::MIN;
    let mut s1c4_best_match = String::new();

    for line in lines {
        let line = line.unwrap();
        let s1c4_result = detect_single_xor(&line);
        let s1c4_message = s1c4_result.0;
        let s1c4_score = s1c4_result.1;
        if s1c4_score > s1c4_best_score {
            s1c4_best_score = s1c4_score;
            s1c4_best_match = String::from(s1c4_message);
        }
    }
    println!("{}", s1c4_best_match);
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
    let s1c5_encoded = set_1::repeating_key_xor(s1c5_string, s1c5_key);
    println!("{}", s1c5_encoded)
}

fn main() -> Result<(), std::io::Error> {
    //let args = Cli::parse();
    s1c1();
    s1c2();
    s1c3();
    s1c4();
    s1c5();

    Ok(())
}

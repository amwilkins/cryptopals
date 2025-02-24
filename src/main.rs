use clap::Parser;
use hex;
use set_1::calc_letter_freq_score;

#[derive(Parser)]
struct Cli {
    hex_string: String,
}

fn main() -> Result<(), std::io::Error> {
    //let args = Cli::parse();

    /* S01C01
      The string:
    49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
    Should produce:
    SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
    So go ahead and make that happen. You'll need to use this code for the rest of the exercises.
    */
    println!("Converting hex into base64:");
    let hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let b64_string = set_1::hex_to_b64(hex_string);
    println!("{}\n", b64_string);

    /* S01C02
    Write a function that takes two equal-length buffers and produces their XOR combination.
    If your function works properly, then when you feed it the string:
    1c0111001f010100061a024b53535009181c
    ... after hex decoding, and when XOR'd against:
    686974207468652062756c6c277320657965
    ... should produce:
    746865206b696420646f6e277420706c6179
    */
    println!("XOR of 2 equal length buffers:");
    let s1 = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
    let s2 = hex::decode("686974207468652062756c6c277320657965").unwrap();
    let xor_string: Vec<u8> = s1.iter().zip(s2.iter()).map(|(&b1, &b2)| b1 ^ b2).collect();
    let output = hex::encode(xor_string);
    println!("{:?}\n", output);

    /* S01C03
    The hex encoded string:
    1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
    ... has been XOR'd against a single character. Find the key, decrypt the message.
    You can do this by hand. But don't: write code to do it for you.
    How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.
    */
    println!("Single byte XOR cipher");
    let s1c3_hex_string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let s1c3_byte_string = hex::decode(s1c3_hex_string).unwrap();
    let mut s1c3_message = String::new();
    let mut best_score = f64::MIN;
    let mut key_byte: u8 = 0;
    for letter in 0..=255 {
        key_byte = letter as u8;
        let s1c3_byte_decoded: Vec<u8> = s1c3_byte_string
            .iter()
            .map(|&byte| byte ^ key_byte)
            .collect();
        let s1c3_string_decoded = String::from_utf8_lossy(&s1c3_byte_decoded);
        let score = calc_letter_freq_score(&s1c3_string_decoded);

        if score > best_score {
            best_score = score;
            s1c3_message = String::from(s1c3_string_decoded);
        }
    }
    println!("Letter: {}, Message: {}", key_byte as char, s1c3_message);

    Ok(())
}

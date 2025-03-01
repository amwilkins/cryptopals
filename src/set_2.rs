use cryptopals::*;
use std::fs;

fn s2c9() {
    /* S02C09
    A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized messages.
    One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.
    So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance,
    "YELLOW SUBMARINE"
    ... padded to 20 bytes would be:
    "YELLOW SUBMARINE\x04\x04\x04\x04"
    */
    println!("\nS02C09 Implement PKCS#7 padding");
    let s2c9_bytes = String::from("YELLOW SUBMARINE").into_bytes();

    let s2c9_out_bytes = pad_block_size(&s2c9_bytes, 20);
    let s2c9_out_string = String::from_utf8(s2c9_out_bytes).unwrap();

    println!(
        "Padded string, len {}: {}",
        s2c9_out_string.len(),
        s2c9_out_string
    );
}
fn s2c10() {
    /* S02C10 Implement CBC mode
    CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a block cipher natively only transforms individual blocks.
    In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.
    The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext block" called the initialization vector, or IV.
    Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise to combine them.
    The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)
    */
    println!("\nS02C10 Implement CBC mode");

    let s2c10_key = "YELLOW SUBMARINE".as_bytes();
    let s2c10_text_bytes = pad_block_size(String::from("This is a secret message.").as_bytes(), 16);

    // encrypt then decrypt
    let s2c10_encrypted = cbc_encrypt(&s2c10_text_bytes, s2c10_key, &[0; 16]);
    let s2c10_decrypted = cbc_decrypt(&s2c10_encrypted, s2c10_key, &[0; 16]);

    println!("{:?}", String::from_utf8_lossy(&s2c10_decrypted));

    //let s1c10_file = fs::read_to_string("data/10.txt").unwrap().replace('\n', "");
    //let s1c10_file_bytes = pad_block_size(&b64_to_byte(&s1c10_file), 16);
    //let s2c10_decrypted_file = cbc_decrypt(&s1c10_file_bytes, s2c10_key, &[0; 16]);
    //println!("{:?}", String::from_utf8_lossy(&s2c10_decrypted_file));
}
fn s2c11() {
    /* S02C11 An ECB/CBC detection oracle
    Now that you have ECB and CBC working:
    Write a function to generate a random AES key; that's just 16 random bytes.
    Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.
    The function should look like:
    encryption_oracle(your-input)
    => [MEANINGLESS JIBBER JABBER]
    Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.
    Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.
    Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.
        */
    println!("\nS02C11 An ECB/CBC detection oracle");
    let s2c11_random_key = generate_random_aes_key();
    println!("Randomly generated AES key: {:?}", s2c11_random_key);

    // detecting which block cipher mode is being used
    let (s2c11_detected_encryption, s2c11_ciphertext) = detect_block_cipher_mode(encryption_oracle);

    println!("Detected encryption method: {}", s2c11_detected_encryption);
    for i in s2c11_ciphertext.chunks(16) {
        println!("{:?}", i)
    }
}

fn s2c12() {
    /* S02C12 Byte-at-a-time ECB decryption (Simple)
     Copy your oracle function to a new function that encrypts buffers under ECB mode using a consistent but unknown key (for instance, assign a single random key, once, to a global variable).
    Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the following string:
    Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK
    Spoiler alert.
    Do not decode this string now. Don't do it.
    Base64 decode the string before appending it. Do not base64 decode the string by hand; make your code do it. The point is that you don't know its contents.
    What you have now is a function that produces:
    AES-128-ECB(your-string || unknown-string, random-key)
    It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!
    Here's roughly how:
        1. Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.
        2. Detect that the function is using ECB. You already know, but do this step anyways.
        3. Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.
        4. Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
        5. Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.
        6. Repeat for the next byte.
         */
    println!("\nS02C12 Byte-at-a-time ECB decryption (Simple)");
    let s2c12_secret_key = generate_random_aes_key();
    println!("Secret key: {:?}", &s2c12_secret_key);
    let mut s2c12_block_size = 0;
    for i in 1..=64 {
        let detection_block = vec![0u8; i];

        let s2c12_ciphertext = s2s12_oracle(
            [detection_block.as_slice(), detection_block.as_slice()]
                .concat()
                .as_slice(),
            &s2c12_secret_key,
        );

        if s2c12_ciphertext
            .chunks(i)
            .next()
            .unwrap()
            .eq(s2c12_ciphertext.chunks(i).nth(1).unwrap())
        {
            s2c12_block_size = i;
            break;
        }
    }
    println!("Found block size {}", s2c12_block_size);

    let mut s2c12_crafted_bytes = vec![65u8; 127];
    let mut s2c12_found_key: Vec<u8> = Vec::new();

    for i in (0..128).rev() {
        println!("Cracking byte: {}", i);
        let s2c12_target = s2s12_oracle(&vec![65; i], &s2c12_secret_key);

        let mut s2c12_matched = false;
        for i in 0..255 {
            let s2c12_oracle_input = [s2c12_crafted_bytes.as_ref(), [i].as_ref()].concat();
            let s2c12_oracle_output = s2s12_oracle(&s2c12_oracle_input, &s2c12_secret_key);

            if s2c12_oracle_output[16..128] == s2c12_target[16..128] {
                s2c12_matched = true;
                s2c12_found_key.push(i as u8);
                s2c12_crafted_bytes = [s2c12_crafted_bytes[1..].to_vec(), [i].to_vec()].concat();
                println!(
                    "Cracked: [{}]",
                    String::from_utf8_lossy(s2c12_found_key.as_ref())
                );
                break;
            }
        }
        if !s2c12_matched {
            break;
        }
    }
    println!("\nFinal discovered key: {:?}", s2c12_found_key);
}

pub fn run() {
    s2c9();
    s2c10();
    s2c11();
    s2c12();
}

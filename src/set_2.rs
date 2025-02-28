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
    println!("\nS02C10 ");

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
    println!("\nS02C11 ");
    let s2c11_random_key = generate_random_aes_key();
    println!("Randomly generated AES key: {:?}", s2c11_random_key);

    // detecting which block cipher mode is being used
    let (s2c11_detected_encryption, s2c11_ciphertext) = detect_block_cipher_mode(encryption_oracle);

    println!("Detected encryption method: {}", s2c11_detected_encryption);
    for i in s2c11_ciphertext.chunks(16) {
        println!("{:?}", i)
    }
}
pub fn run() {
    s2c9();
    s2c10();
    s2c11();
}

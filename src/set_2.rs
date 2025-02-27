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
    let s1c10_file_bytes = pad_block_size(
        fs::read_to_string("data/10.txt")
            .unwrap()
            .replace('\n', "")
            .as_bytes(),
        16,
    );

    let s2c10_encrypted = cbc_encrypt(&s2c10_text_bytes, s2c10_key, &['\x00' as u8; 16]);
    println!("{:?}", s2c10_encrypted)
    //let s2c10_decrypted = cbc_decrypt(s2c10_encrypted, s2c10_key, iv);
}
pub fn run() {
    s2c9();
    s2c10();
}

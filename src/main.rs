// External crate dependencies
extern crate aes;
extern crate block_modes;
extern crate colored;
extern crate generic_array;
extern crate rand;

// Import necessary modules and traits
use aes::{Aes256, NewBlockCipher};
use block_modes::{Cbc, BlockMode, block_padding::Pkcs7};
use colored::*;
use generic_array::GenericArray;
use rand::Rng;
use std::fs;
use std::io::{self, Write};

// Define the type for AES256 in CBC mode with PKCS7 padding
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

// Function to read a file and return its content as bytes
fn read_file(file_path: &str) -> std::io::Result<Vec<u8>> {
    fs::read(file_path)
}

// Function to write data to a file
fn write_file(file_path: &str, data: &[u8]) -> std::io::Result<()> {
    fs::write(file_path, data)
}

// Prompt the user for input and return their response
fn prompt_for_data(prompt: &str) -> String {
    print!("{}: ", prompt);
    io::stdout().flush().unwrap();
    
    let mut data = String::new();
    io::stdin().read_line(&mut data).unwrap();
    data.trim().to_string()
}

// Generate a 32-byte key for AES-256 encryption
fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill(&mut key);
    key
}

// Generate a 16-byte initialization vector (IV)
fn generate_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    rand::thread_rng().fill(&mut iv);
    iv
}

// Convert a byte slice to a hexadecimal string representation
fn bytes_to_hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

// Encrypt data using AES-256 in CBC mode
fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher_key = GenericArray::from_slice(key);
    let cipher = Aes256::new(&cipher_key);
    let initialization_vector = GenericArray::from_slice(iv);
    let cbc = Aes256Cbc::new(cipher, &initialization_vector);
    cbc.encrypt_vec(data)
}

// Decrypt data using AES-256 in CBC mode
fn decrypt(cipher_text: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher_key = GenericArray::from_slice(key);
    let cipher = Aes256::new(&cipher_key);
    let initialization_vector = GenericArray::from_slice(iv);
    let cbc = Aes256Cbc::new(cipher, &initialization_vector);
    cbc.decrypt_vec(cipher_text).unwrap()
}

// Main function
fn main() {
    // Greet the user and ask for their choice: encrypt or decrypt
    println!("{}", "Would you like to encrypt or decrypt a file?".red().bold());
    print!("Enter 'encrypt' or 'decrypt': ");
    io::stdout().flush().unwrap();
    
    let mut choice = String::new();
    io::stdin().read_line(&mut choice).unwrap();
    let choice = choice.trim().to_lowercase();

    match choice.as_str() {
        // Encryption process
        "encrypt" => {
            let input_file = prompt_for_data("Enter the path to the input file");
            let output_file = prompt_for_data("Enter the directory to save the encrypted output (e.g., /path/to/directory/encrypted_data.txt)");
            
            let key = generate_key();
            let iv = generate_iv();

            println!("Generated Key (hex): {}", bytes_to_hex_string(&key));
            println!("Generated IV (hex): {}", bytes_to_hex_string(&iv));
            
            let data = read_file(&input_file).expect("Failed to read the input file");
            let encrypted_data = encrypt(&data, &key, &iv);
            
            // Check if the directory exists, if not, create it
            if let Some(parent) = std::path::Path::new(&output_file).parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent).expect("Failed to create directory");
                }
            }

            write_file(&output_file, &encrypted_data).expect("Failed to write encrypted data");
            println!("Encryption successful. Encrypted file saved at: {}", output_file);
        },
        // Decryption process
        "decrypt" => {
            let input_file = prompt_for_data("Enter the path to the encrypted file");
            let output_file = prompt_for_data("Enter the path to save the decrypted output");
            let key_str = prompt_for_data("Enter the 32-byte key used for encryption");
            let iv_str = prompt_for_data("Enter the 16-byte initialization vector used for encryption");
            
            let key: Vec<u8> = key_str.as_bytes().to_vec();
            let iv: Vec<u8> = iv_str.as_bytes().to_vec();

            if key.len() != 32 || iv.len() != 16 {
                println!("Invalid key or IV length. Exiting.");
                return;
            }
            
            let encrypted_data = read_file(&input_file).expect("Failed to read the encrypted file");
            let decrypted_data = decrypt(&encrypted_data, &key, &iv);
            write_file(&output_file, &decrypted_data).expect("Failed to write decrypted data");
            
            println!("Decryption successful. Decrypted file saved at: {}", output_file);
        },
        // Handle invalid choices
        _ => {
            println!("Invalid choice. Please enter 'encrypt' or 'decrypt'.");
            return;
        }
    }
}

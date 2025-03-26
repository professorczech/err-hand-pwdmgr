// main.rs
// Our main CLI logic and teaching moment for panic! vs Result
// Let's demonstrate a password encryption utility with simple file storage.

mod crypto;

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use crypto::{encrypt_password, decrypt_password};

fn main() {
    // Hardcoded key here for demo. Don't do this in production, eh?
    // Use a proper key vault or derive from user passphrase.
    let key = b"ThisIs32ByteLongPassphraseForAES";

    println!("Welcome to the Rusty Password Locker 🇨🇦");
    println!("1. Save new password");
    println!("2. Retrieve stored password");

    let mut choice = String::new();
    io::stdin().read_line(&mut choice).unwrap();

    match choice.trim() {
        "1" => save_password(key),
        "2" => get_password(key),
        _ => println!("Sorry bud, that's not a valid choice."),
    }
}

// This function demonstrates graceful error handling using Result
fn save_password(key: &[u8]) {
    let mut site = String::new();
    let mut password = String::new();

    println!("Enter the website name:");
    io::stdin().read_line(&mut site).unwrap();

    println!("Enter the password:");
    io::stdin().read_line(&mut password).unwrap();

    // Encrypt the password. If this fails, it's recoverable, so we use Result.
    match encrypt_password(key, password.trim()) {
        Ok(encrypted) => {
            let entry = format!("{}: {}\n", site.trim(), encrypted);
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open("passwords.txt")
                .expect("Failed to open password file."); // Panic here is fine — it's an unrecoverable dev error
            file.write_all(entry.as_bytes()).expect("Write failed."); // Same deal
            println!("Password saved, beauty.");
        },
        Err(e) => println!("Error encrypting password: {}", e),
    }
}

// This function reads stored data and attempts decryption.
// We're handling errors Rust-style — match + Result.
fn get_password(key: &[u8]) {
    let content = fs::read_to_string("passwords.txt")
        .expect("Couldn’t read password file. Maybe it doesn't exist yet?");

    for line in content.lines() {
        let parts: Vec<&str> = line.split(": ").collect();
        if parts.len() != 2 {
            println!("Skipping malformed line.");
            continue;
        }

        let site = parts[0];
        let encrypted = parts[1];

        match decrypt_password(key, encrypted) {
            Ok(password) => println!("{} => {}", site, password),
            Err(_) => println!("Couldn't decrypt password for {}", site),
        }
    }
}

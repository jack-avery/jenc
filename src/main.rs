mod crypt;
mod error;
mod file;

use std::{
    io::{stdin, stdout, Write},
    path::PathBuf,
};

use crate::error::JencError;

use clap::Parser;
use clap_num::number_range;

#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    #[arg(long, short, help = "Use <PASSWORD> instead of prompting")]
    password: Option<String>,

    #[arg(long, short, value_parser=bcrypt_cost_bounds, help="Use <COST> as bcrypt hash cost instead of prompting")]
    cost: Option<u8>,

    #[arg(
        long,
        short,
        action,
        conflicts_with = "decrypt",
        help = "Encrypt <FILE>"
    )]
    encrypt: bool,

    #[arg(
        long,
        short,
        action,
        conflicts_with = "encrypt",
        help = "Decrypt <FILE>"
    )]
    decrypt: bool,

    file: String,
}

enum JencMode {
    Encrypt,
    Decrypt,
}

fn bcrypt_cost_bounds(s: &str) -> Result<u8, String> {
    number_range(s, 5, 31)
}

fn main() {
    let args: Args = Args::parse();
    match match get_mode(&args.file, &args.encrypt, &args.decrypt) {
        JencMode::Encrypt => jenc_encrypt(&args.file, args.password, args.cost),
        JencMode::Decrypt => jenc_decrypt(&args.file, args.password),
    } {
        Ok(s) => println!("{}", s),
        Err(s) => eprintln!("{}", s),
    }
}

fn get_mode(file: &str, encrypt_flag: &bool, decrypt_flag: &bool) -> JencMode {
    let path: PathBuf = PathBuf::from(file);
    if (!encrypt_flag && !decrypt_flag) && // neither -e or -d set: detect
        path.is_file() && // it is a file
        file.ends_with(".jenc")
    // it is a .jenc file
    {
        return JencMode::Decrypt;
    }
    JencMode::Encrypt
}

fn jenc_encrypt(file: &str, pass: Option<String>, cost: Option<u8>) -> Result<String, JencError> {
    let password: String = match pass {
        Some(p) => p,
        None => get_password("password")?,
    };
    let bcrypt_cost: u8 = match cost {
        Some(c) => c,
        None => get_cost()?,
    };
    file::encrypt(file, &password, bcrypt_cost)?;
    Ok("ok".to_string())
}

fn jenc_decrypt(file: &str, pass: Option<String>) -> Result<String, JencError> {
    let password: String = match pass {
        Some(p) => p,
        None => get_password("password")?,
    };
    file::decrypt(file, &password)?;
    Ok("ok".to_string())
}

fn get_cost() -> Result<u8, JencError> {
    let mut cost: String = String::new();
    loop {
        cost.clear();
        print!("crypt slowness (5-31, higher = slower, 12-13 is good): ");
        stdout().flush()?;
        stdin().read_line(&mut cost)?.to_string();
        let trim: &str = cost.trim();

        match trim.parse::<u8>() {
            Ok(u) => {
                if !(5..=31).contains(&u) {
                    println!("out of range");
                    continue;
                }
                return Ok(u);
            }
            Err(_) => {
                println!("not a valid number");
            }
        }
    }
}

fn get_password(prompt: &str) -> Result<String, JencError> {
    print!("{}: ", prompt);
    stdout().flush()?;
    Ok(rpassword::read_password()?)
}

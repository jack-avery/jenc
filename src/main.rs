mod crypt;
mod errors;
mod file;

use std::{
    env,
    io::{stdin, stdout, Write},
    path::PathBuf
};

use crate::errors::{
    Result,
    JencError::NoParam,
};

fn main() {
    let args: Vec<String> = env::args().collect();
    let action: &str = match args.get(1) {
        Some(action) => action,
        None => "help",
    };
    let param: Option<&String> = args.get(2);

    let out: Result<String> = match action {
        "encrypt" => jenc_encrypt(&param),
        "enc" => jenc_encrypt(&param),
        "e" => jenc_encrypt(&param),

        "decrypt" => jenc_decrypt(&param),
        "dec" => jenc_decrypt(&param),
        "d" => jenc_decrypt(&param),

        _ => attempt_autodetect_action(action),
    };

    if out.is_err() {
        println!("error: {}", out.unwrap_err());
    } else {
        println!("{}", out.unwrap());
    }
}

fn attempt_autodetect_action(param: &str) -> Result<String> {
    let path: PathBuf = PathBuf::from(param);

    if path.is_file() {
        if param.ends_with(".jenc") {
            println!("detected decrypt jenc...");
            return jenc_decrypt(&Some(&param.to_string()))
        } else {
            println!("detected encrypt file...");
            return jenc_encrypt(&Some(&param.to_string()))
        }
    }
    else if path.is_dir() {
        println!("detected encrypt folder...");
        return jenc_encrypt(&Some(&param.to_string()))
    }

    Ok(help())
}

fn jenc_encrypt(param: &Option<&String>) -> Result<String> {
    param_check(param)?;
    let file: &str = param.unwrap();

    let pass: String = get_password("password")?;
    let cost: u8 = get_cost()?;

    file::encrypt(file, &pass, cost)?;

    Ok("ok".to_string())
}

fn jenc_decrypt(param: &Option<&String>) -> Result<String> {
    param_check(param)?;
    let file: &str = param.unwrap();

    let pass: String = get_password("password")?;

    file::decrypt(file, &pass)?;

    Ok("ok".to_string())
}

fn get_cost() -> Result<u8> {
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

fn get_password(prompt: &str) -> Result<String> {
    print!("{}: ", prompt);
    stdout().flush()?;
    Ok(rpassword::read_password()?)
}

fn param_check(param: &Option<&String>) -> Result<()> {
    if param.is_none() {
        return Err(NoParam);
    }
    Ok(())
}

fn help() -> String {
    format!(
        "jenc v{}

primitive file encryption tool.
jenc deletes the original file.

usage:
    encrypt <file>          encrypts to <file>.jenc
    (shortform: enc, e)

    decrypt <file>.jenc     decrypts to <file> 
    (shortform: dec, d)

examples:
    jenc e myfile.txt
    jenc dec myfile.txt.jenc",
        env!("CARGO_PKG_VERSION")
    )
}

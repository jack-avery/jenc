use std::{
    fs::{read, remove_dir_all, remove_file, write, File},
    path::PathBuf,
};

use rand::{distributions::Alphanumeric, Rng};

use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use tar::{Archive, Builder};

use crate::crypt::{aes256_decrypt, aes256_encrypt, CryptValue};
use crate::error::JencError;

/// Generates a filename consisting of 6 random alphanumeric characters
/// and the .tar.gz extension
fn random_tar_name() -> String {
    let name: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(6)
        .map(char::from)
        .collect();
    format!("{}.tar.gz", name)
}

/// Encrypt `path` using `pass` to a `.jenc` file,
/// keeping the original file if `keep` is `true`.
///
/// Returns `()` if encryption completed successfully.
/// Returns `JencError` if a step of the encryption failed.
pub fn encrypt(path: &str, pass: &str, cost: u8, keep: &bool) -> Result<(), JencError> {
    let in_path: PathBuf = PathBuf::from(path);
    let working_tar: String = random_tar_name();

    // .tar.gz the folder
    let tar_gz: File = File::create(&working_tar)?;
    let mut encoder: GzEncoder<File> = GzEncoder::new(tar_gz, Compression::default());
    {
        let mut archive: Builder<&mut GzEncoder<File>> = Builder::new(&mut encoder);
        if in_path.is_file() {
            archive
                .append_file(&in_path, &mut File::open(&in_path)?)
                .unwrap();
        } else {
            archive.append_dir_all(&in_path, &in_path).unwrap();
        }
    }
    encoder.finish()?;

    // read tar and encrypt
    let raw: Vec<u8> = read(&working_tar)?;
    let enc: Vec<u8> = aes256_encrypt(&raw, pass, cost)?;

    // save original path
    let mut out_path: PathBuf = in_path.clone();

    // write to .jenc
    out_path.set_extension("jenc");
    write(&out_path, enc)?;

    // clean up
    if !keep {
        if in_path.is_file() {
            remove_file(&in_path)?;
        } else {
            remove_dir_all(&in_path)?;
        }
    }
    remove_file(&working_tar)?;

    Ok(())
}

/// Decrypt `file` using `pass`,
/// keeping the encrypted file if `keep` is `true`.
///
/// Returns `()` if decryption completed successfully.
/// Returns `JencError` if a step of the decryption failed.
pub fn decrypt(file: &str, pass: &str, keep: &bool) -> Result<(), JencError> {
    let in_path: PathBuf = PathBuf::from(file);
    let working_tar = random_tar_name();

    // read and decrypt
    let raw: Vec<u8> = read(&in_path)?;
    let dec: CryptValue = aes256_decrypt(&raw, pass)?;

    // write decrypted to a working tar.gz
    write(&working_tar, dec.value)?;

    // extract and inflate the decrypted tar.gz
    let tar_gz: File = File::open(&working_tar)?;
    let tar: GzDecoder<File> = GzDecoder::new(tar_gz);
    let mut archive: Archive<GzDecoder<File>> = Archive::new(tar);
    archive.unpack(".")?;

    // clean up
    if !keep {
        remove_file(&in_path)?;
    }
    remove_file(&working_tar)?;

    Ok(())
}

use std::{
    fs::{read, remove_dir_all, remove_file, write, File},
    path::PathBuf,
};

use rand::{distributions::Alphanumeric, Rng};

use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use tar::{Archive, Builder};

use crate::crypt::{aes256_decrypt, aes256_encrypt, CryptValue};
use crate::error::JencError;

pub fn encrypt(file: &str, pass: &str, cost: u8) -> Result<(), JencError> {
    let mut path: PathBuf = PathBuf::from(file);

    // use randomly generated tar name to (try to) avoid file conflicts
    let _name: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(6)
        .map(char::from)
        .collect();
    let working_tar = format!("{}.tar.gz", _name);

    // .tar.gz the folder
    let tar_gz: File = File::create(&working_tar)?;
    let mut encoder: GzEncoder<File> = GzEncoder::new(tar_gz, Compression::default());
    {
        let mut archive: Builder<&mut GzEncoder<File>> = Builder::new(&mut encoder);
        if path.is_file() {
            archive.append_file(&path, &mut File::open(&path)?).unwrap();
        } else {
            archive.append_dir_all(&path, &path).unwrap();
        }
    }
    encoder.finish()?;

    // read tar and encrypt
    let raw: Vec<u8> = read(&working_tar)?;
    let enc: Vec<u8> = aes256_encrypt(&raw, pass, cost)?;

    // clean up
    if path.is_file() {
        remove_file(&path)?; 
    } else {
        remove_dir_all(&path)?;
    }   
    remove_file(&working_tar)?;

    // write to .jenc
    path.set_extension("jenc");
    write(&path, enc)?;

    Ok(())
}

pub fn decrypt(file: &str, pass: &str) -> Result<(), JencError> {
    let mut path: PathBuf = PathBuf::from(file);

    // read and decrypt
    let raw: Vec<u8> = read(&path)?;
    let dec: CryptValue = aes256_decrypt(&raw, pass)?;

    // clean up
    remove_file(&path)?;

    // write to original
    path.set_extension("");
    write(&path, dec.value)?;

    // tarballed folders: also extract and inflate
    let tar_gz: File = File::open(&path)?;
    let tar: GzDecoder<File> = GzDecoder::new(tar_gz);
    let mut archive: Archive<GzDecoder<File>> = Archive::new(tar);
    archive.unpack(".")?;

    // clean up
    remove_file(&path)?;

    Ok(())
}

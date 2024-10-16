use std::{
    fs::{read, remove_dir_all, remove_file, write, File},
    path::PathBuf,
};

use rand::{distributions::Alphanumeric, Rng};

use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use tar::{Archive, Builder};

use crate::crypt::{aes256_decrypt, aes256_encrypt, CryptValue};
use crate::error::JencError;

pub fn encrypt(file: &str, pass: &str, cost: u8, keep: &bool) -> Result<(), JencError> {
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

    // save original path
    let original_path: PathBuf = path.clone();

    // write to .jenc
    path.set_extension("jenc");
    write(&path, enc)?;

    // clean up
    if !keep {
        if original_path.is_file() {
            remove_file(&original_path)?;
        } else {
            remove_dir_all(&original_path)?;
        }
    }
    remove_file(&working_tar)?;

    Ok(())
}

pub fn decrypt(file: &str, pass: &str, keep: &bool) -> Result<(), JencError> {
    let jenc_path: PathBuf = PathBuf::from(file);

    // read and decrypt
    let raw: Vec<u8> = read(&jenc_path)?;
    let dec: CryptValue = aes256_decrypt(&raw, pass)?;

    // write to original
    let mut working_tar: PathBuf = jenc_path.clone();
    working_tar.set_extension("tar.gz");
    write(&working_tar, dec.value)?;

    // tarballed folders: also extract and inflate
    let tar_gz: File = File::open(&working_tar)?;
    let tar: GzDecoder<File> = GzDecoder::new(tar_gz);
    let mut archive: Archive<GzDecoder<File>> = Archive::new(tar);
    archive.unpack(".")?;

    // clean up
    if !keep {
        remove_file(&jenc_path)?;
    }
    remove_file(&working_tar)?;

    Ok(())
}

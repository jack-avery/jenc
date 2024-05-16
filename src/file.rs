use std::{
    fs::{read, remove_dir_all, remove_file, write, File},
    path::PathBuf
};

use flate2::{
    write::GzEncoder,
    read::GzDecoder,
    Compression
};
use tar::{Archive, Builder};

use crate::crypt::{aes256_decrypt, aes256_encrypt, CryptValue};
use crate::errors::Result;

pub fn encrypt(file: &str, pass: &str, cost: u8) -> Result<()> {
    let mut path: PathBuf = PathBuf::from(file);

    // handle files: encrypt directly
    if path.is_file() {
        // read original and encrypt
        let raw: Vec<u8> = read(&path)?;
        let enc: Vec<u8> = aes256_encrypt(&raw, pass, cost)?;

        // clean up
        remove_file(&path)?;

        // write to .jenc
        match path.extension() {
            Some(ext_old) => {
                let ext: String = format!("{}.jenc", ext_old.to_str().unwrap());
                path.set_extension(ext);
            }
            None => {
                path.set_extension("jenc");
            }
        }
        write(&path, enc)?;

    // handle folders: create a .tar.gz
    } else {
        let tar_gz: File = File::create("archive.tar.gz")?;
        let mut encoder: GzEncoder<File> = GzEncoder::new(tar_gz, Compression::default());
        {
            let mut archive: Builder<&mut GzEncoder<File>> = Builder::new(&mut encoder);
            archive.append_dir_all(&path, &path).unwrap();
        }
        encoder.finish()?;

        // read original and encrypt
        let raw: Vec<u8> = read("archive.tar.gz")?;
        let enc: Vec<u8> = aes256_encrypt(&raw, pass, cost)?;

        // clean up
        remove_dir_all(&path)?;
        remove_file("archive.tar.gz")?;
        
        // write to .jenc
        path.set_extension("tar.gz.jenc");
        write(&path, enc)?;
    }

    Ok(())
}

pub fn decrypt(file: &str, pass: &str) -> Result<()> {
    let mut path: PathBuf = PathBuf::from(file);

    // read and decrypt
    let raw: Vec<u8> = read(&path)?;
    let dec: CryptValue = aes256_decrypt(&raw, pass)?;

    // clean up
    remove_file(&path)?;

    // write to original
    path.set_extension("");
    write(&path, dec.value)?;

    // tarballed folders: unzip
    if let Some(ext) = path.extension() {
        let ext_str: &str = ext.to_str().unwrap();
        if ext_str == "gz" {
            let tar_gz: File = File::open(&path)?;
            let tar: GzDecoder<File> = GzDecoder::new(tar_gz);
            let mut archive: Archive<GzDecoder<File>> = Archive::new(tar);
            archive.unpack(".")?;

            // clean up
            remove_file(&path)?;
        }
    }

    Ok(())
}

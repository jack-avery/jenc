# jenc
> the janky file encryption tool

jenc is a password-based **file encryption** tool.

## :hammer_and_wrench: Installation
1. Install [Rust & Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html).
2. Run `cargo build --release` to create the executable for your system.

The executable will be in the `target/release` folder.

## :writing_hand: Usage
```
primitive file encryption tool.
jenc deletes the original file.

usage:
    encrypt <file>          encrypts to <file>.jenc
    (shortform: enc, e)

    decrypt <file>.jenc     decrypts to <file> 
    (shortform: dec, d)

examples:
    jenc e myfile.txt
    jenc dec myfile.txt.jenc
```

## :bug: Bug reports & feature suggestions
Has something gone **horribly** wrong? *Or do you just think something's missing?*

Feel free to [create a new issue](https://github.com/jack-avery/jenc/issues).

# jenc
> the janky file encryption tool

jenc is a password-based **file encryption** tool.

## :hammer_and_wrench: Installation
1. Install [Rust & Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html).
2. Run `cargo install --path .` to build and install the executable.

## :writing_hand: Usage
```
Usage: jenc.exe [OPTIONS] <FILE>

Arguments:
  <FILE>

Options:
  -p, --password <PASSWORD>  Use <PASSWORD> instead of prompting
  -c, --cost <COST>          Use <COST> as bcrypt hash cost instead of prompting
  -e, --encrypt              Encrypt <FILE>
  -d, --decrypt              Decrypt <FILE>
  -h, --help                 Print help
  -V, --version              Print version
```

## :bug: Bug reports & feature suggestions
Has something gone **horribly** wrong? *Or do you just think something's missing?*

Feel free to [create a new issue](https://github.com/jack-avery/jenc/issues).

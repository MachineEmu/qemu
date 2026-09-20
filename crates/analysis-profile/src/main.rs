use analysis_profile::{clone_identity_json, validate_json};
use std::{
    env, fs,
    io::{self, Read},
};

fn input(path: Option<String>) -> io::Result<String> {
    match path {
        Some(path) => fs::read_to_string(path),
        None => {
            let mut value = String::new();
            io::stdin().read_to_string(&mut value).map(|_| value)
        }
    }
}

fn main() {
    let mut args = env::args().skip(1);
    let result = match args.next().as_deref() {
        Some("validate") => {
            input(args.next()).and_then(|value| validate_json(&value).map_err(io::Error::other))
        }
        Some("clone-identity") => match (args.next(), args.next(), args.next()) {
            (Some(seed), Some(clone), None) => {
                clone_identity_json(&seed, &clone).map_err(io::Error::other)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "usage: analysis-profile clone-identity <seed> <clone-id>",
            )),
        },
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: analysis-profile validate [json-file] | clone-identity <seed> <clone-id>",
        )),
    };
    match result {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("analysis profile rejected: {error}");
            std::process::exit(2);
        }
    }
}

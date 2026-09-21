use analysis_profile::{acpi_dump_json, clone_identity_json, validate_json};
use std::{
    env, fs,
    io::{self, Read},
    path::{Path, PathBuf},
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
        Some("acpi-dump") => {
            let mut metadata_only = false;
            let mut output_dir: Option<PathBuf> = None;
            let parsed = (|| {
                while let Some(argument) = args.next() {
                    match argument.as_str() {
                        "--metadata-only" => metadata_only = true,
                        "--output-dir" => {
                            output_dir = Some(PathBuf::from(args.next().ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "--output-dir requires DIR",
                                )
                            })?));
                        }
                        _ => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "usage: analysis-profile acpi-dump [--metadata-only] [--output-dir DIR]",
                            ));
                        }
                    }
                }
                Ok::<(), io::Error>(())
            })();
            parsed.and_then(|_| {
                acpi_dump_json(Path::new("/"), !metadata_only, output_dir.as_deref())
                    .map_err(io::Error::other)
            })
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: analysis-profile validate [json-file] | clone-identity <seed> <clone-id> | acpi-dump [--metadata-only] [--output-dir DIR]",
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

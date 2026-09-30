use minimint_ng::daemon::{
    options::{self, Command},
    process, resolve,
    shutdown::Shutdown,
};
use std::{process::ExitCode, time::Duration};
fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    // The parent supervises this isolated resolver process. This internal mode
    // loads no configuration, secrets, storage, signal handlers or workers.
    if args
        .first()
        .is_some_and(|arg| arg == "--internal-resolve-authority")
    {
        return if args.len() == 2 && resolve::run_helper(&args[1]).is_ok() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }
    let command = match options::parse(args) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    match command {
        Command::Help => {
            print!("{}", options::USAGE);
            ExitCode::SUCCESS
        }
        Command::Version => {
            println!("minimint-ng/{}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Command::Run(options) => {
            let shutdown = match Shutdown::install(Duration::from_secs(30)) {
                Ok(shutdown) => shutdown,
                Err(_) => {
                    eprintln!("Cannot install guardian shutdown handlers");
                    return ExitCode::FAILURE;
                }
            };
            let result = process::run(*options, &shutdown);
            let finished = shutdown.finish();
            if let Err(error) = result {
                eprintln!("{error}");
                return ExitCode::FAILURE;
            }
            if finished.is_err() {
                eprintln!("Guardian shutdown watchdog failed");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
    }
}

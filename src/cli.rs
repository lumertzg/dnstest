use std::ffi::OsStr;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use usage_rs::Cli;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Run DNS tests written in Lua.
#[derive(Cli)]
#[usage(bin = "dnstest", version, unknown_flags = "error")]
struct Args {
    /// Lua files or directories. Directories are searched recursively for .lua files.
    #[usage(default = "tests", value_name = "PATH", value_hint = usage_rs::ValueHint::FilePath)]
    paths: Vec<PathBuf>,
    /// Maximum concurrent test files. Tests within a file always run serially.
    #[usage(short = 'j', long, default = "4")]
    jobs: NonZeroUsize,
    /// Print the agent skill for writing and running DNS tests, then exit.
    #[usage(long)]
    skill: bool,
}

pub enum Command {
    Run {
        files: Vec<PathBuf>,
        jobs: NonZeroUsize,
    },
    Skill,
}

pub fn command() -> Result<Command> {
    let args = Args::parse();
    if args.skill {
        return Ok(Command::Skill);
    }

    let mut files = Vec::new();
    for path in args.paths {
        let metadata = std::fs::metadata(&path).map_err(|error| context(&path, error))?;
        if metadata.is_file() && path.extension() != Some(OsStr::new("lua")) {
            return Err(format!("expected a Lua file: {}", path.display()).into());
        }

        // Explicit paths follow symlinks. Only entries found while walking directories skip them.
        collect(&path, &metadata, &mut files)?;
    }

    files.sort();
    files.dedup();
    if files.is_empty() {
        return Err("no Lua test files found".into());
    }

    Ok(Command::Run {
        files,
        jobs: args.jobs,
    })
}

fn collect(path: &Path, metadata: &std::fs::Metadata, files: &mut Vec<PathBuf>) -> Result<()> {
    if metadata.is_dir() {
        for entry in std::fs::read_dir(path).map_err(|error| context(path, error))? {
            let path = entry.map_err(|error| context(path, error))?.path();
            let metadata =
                std::fs::symlink_metadata(&path).map_err(|error| context(&path, error))?;
            if !metadata.is_symlink() {
                collect(&path, &metadata, files)?;
            }
        }
    } else if path.extension() == Some(OsStr::new("lua")) {
        files.push(path.canonicalize().map_err(|error| context(path, error))?);
    }

    Ok(())
}

fn context(path: &Path, error: std::io::Error) -> String {
    format!("{}: {error}", path.display())
}

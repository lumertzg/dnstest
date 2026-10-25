mod cli;
mod dns;
mod output;
mod runner;

use std::process::ExitCode;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match cli::command() {
        Ok(cli::Command::Skill) => {
            print!("{}", include_str!("../.agents/skills/testing-dns/SKILL.md"));
            ExitCode::SUCCESS
        }
        Ok(cli::Command::Run { files, jobs }) => match runner::run(&files, jobs.get()).await {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::FAILURE,
            Err(error) => fail(error),
        },
        Err(error) => fail(error),
    }
}

fn fail(error: impl std::fmt::Display) -> ExitCode {
    eprintln!("dnstest: {error}");
    ExitCode::FAILURE
}

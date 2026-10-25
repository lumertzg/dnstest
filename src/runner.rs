use std::path::{Path, PathBuf};
use std::time::Instant;

use futures_util::{StreamExt, stream};
use mlua::{Error, Function, Lua, Table};

use crate::{dns, output};

#[derive(Default)]
struct FileReport {
    passed: usize,
    failed: usize,
    errors: usize,
    output: String,
}

pub async fn run(files: &[PathBuf], jobs: usize) -> mlua::Result<bool> {
    let started = Instant::now();
    let (mut passed, mut failed, mut file_errors) = (0, 0, 0);
    println!("\n RUN  dnstest v{}\n", env!("CARGO_PKG_VERSION"));
    let mut reports = stream::iter(files.iter().map(|path| run_file(path))).buffered(jobs);

    while let Some(report) = reports.next().await {
        let report = report?;
        passed += report.passed;
        failed += report.failed;
        file_errors += report.errors;
        println!("{}", report.output);
    }

    output::summary(passed, failed, file_errors, started.elapsed());
    Ok(failed == 0 && file_errors == 0)
}

async fn run_file(path: &Path) -> mlua::Result<FileReport> {
    let started = Instant::now();
    let display = path.strip_prefix(std::env::current_dir()?).unwrap_or(path);
    let mut report = FileReport {
        output: format!(" {}\n", display.display()),
        ..FileReport::default()
    };
    let lua = Lua::new();
    dns::install(&lua)?;
    let api: Table = lua
        .load(include_str!("api.lua"))
        .set_name("@dnstest/api.lua")
        .eval()?;
    let loaded = async {
        let source = std::fs::read_to_string(path)?;
        lua.load(&source)
            .set_name(format!("@{}", display.display()))
            .exec_async()
            .await
    }
    .await;
    api.get::<Function>("seal")?.call::<()>(())?;
    report.output.push_str(&take_logs(&api)?);

    if let Err(error) = loaded {
        report.errors = 1;
        report
            .output
            .push_str(&output::test("file load", started.elapsed(), Some(&error)));
        return Ok(report);
    }

    let tests: Table = api.get("tests")?;
    if tests.is_empty() {
        report.errors = 1;
        report.output.push_str(&output::test(
            "file load",
            started.elapsed(),
            Some(&Error::runtime("no tests registered")),
        ));
    }

    for test in tests.sequence_values::<Table>() {
        let test = test?;
        let name: String = test.get("name")?;
        let callback: Function = test.get("run")?;
        let started = Instant::now();
        let result = callback.call_async::<()>(()).await;
        if result.is_ok() {
            report.passed += 1;
        } else {
            report.failed += 1;
        }
        report.output.push_str(&output::test(
            &name,
            started.elapsed(),
            result.as_ref().err(),
        ));
        report.output.push_str(&take_logs(&api)?);
    }

    Ok(report)
}

fn take_logs(api: &Table) -> mlua::Result<String> {
    let logs: Table = api.get("logs")?;
    let mut output = String::new();
    for line in logs.sequence_values::<String>() {
        for line in line?.lines() {
            output.push_str(&format!("    {line}\n"));
        }
    }
    logs.clear()?;

    Ok(output)
}

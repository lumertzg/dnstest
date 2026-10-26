use std::path::{Component, Path, PathBuf};
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

pub async fn run(files: &[PathBuf], jobs: usize) -> bool {
    let started = Instant::now();
    let (mut passed, mut failed, mut file_errors) = (0, 0, 0);
    println!("\n RUN  dnstest v{}\n", env!("CARGO_PKG_VERSION"));
    let cwd = std::env::current_dir()
        .and_then(|cwd| cwd.canonicalize())
        .ok();
    let mut reports = stream::iter(files.iter().map(|path| {
        let display = cwd
            .as_deref()
            .map_or_else(|| path.clone(), |cwd| relative(path, cwd));
        run_file(path, display)
    }))
    .buffered(jobs);

    while let Some(report) = reports.next().await {
        passed += report.passed;
        failed += report.failed;
        file_errors += report.errors;
        println!("{}", report.output);
    }

    output::summary(passed, failed, file_errors, started.elapsed());
    failed == 0 && file_errors == 0
}

/// Shortens Lua chunk names, which Lua truncates to about 60 bytes in error messages.
fn relative(path: &Path, base: &Path) -> PathBuf {
    let common = path
        .components()
        .zip(base.components())
        .take_while(|(left, right)| left == right)
        .count();
    let parents = base.components().skip(common).map(|_| Component::ParentDir);
    let relative: PathBuf = parents.chain(path.components().skip(common)).collect();

    if common == 0 || relative.as_os_str().len() >= path.as_os_str().len() {
        path.to_owned()
    } else {
        relative
    }
}

async fn run_file(path: &Path, display: PathBuf) -> FileReport {
    let started = Instant::now();
    let mut report = FileReport {
        output: format!(" {}\n", display.display()),
        ..FileReport::default()
    };

    // Runner failures belong to this file and must not discard other files' results.
    if let Err(error) = execute(path, &display, &mut report).await {
        report.errors += 1;
        report
            .output
            .push_str(&output::test("runner", started.elapsed(), Some(&error)));
    }

    report
}

async fn execute(path: &Path, display: &Path, report: &mut FileReport) -> mlua::Result<()> {
    let started = Instant::now();
    let lua = Lua::new();
    dns::install(&lua)?;
    let api: Table = lua
        .load(include_str!("api.lua"))
        .set_name(output::API_CHUNK)
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
        return Ok(());
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

    Ok(())
}

fn take_logs(api: &Table) -> mlua::Result<String> {
    let logs: Table = api.get("logs")?;
    let mut text = String::new();
    for chunk in logs.sequence_values::<mlua::LuaString>() {
        text.push_str(&chunk?.to_string_lossy());
    }
    logs.clear()?;

    let mut output = String::new();
    for line in text.lines() {
        output.push_str(&format!("    {line}\n"));
    }

    Ok(output)
}

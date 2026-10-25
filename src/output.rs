use std::io::{self, IsTerminal};
use std::time::Duration;

pub fn label(text: &str, passed: bool) -> String {
    if io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none() {
        let color = if passed { 32 } else { 31 };
        format!("\x1b[{color}m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

pub fn test(name: &str, elapsed: Duration, error: Option<&mlua::Error>) -> String {
    let mark = label(if error.is_none() { "✓" } else { "×" }, error.is_none());
    let mut output = format!(
        "  {mark} {name} ({:.1} ms)\n",
        elapsed.as_secs_f64() * 1000.0
    );
    if let Some(error) = error {
        for line in error.to_string().lines() {
            output.push_str(&format!("      {line}\n"));
        }
    }

    output
}

pub fn summary(passed: usize, failed: usize, file_errors: usize, elapsed: Duration) {
    println!(
        "\n  Tests  {} passed | {} failed\n  Files  {} failed to load\n   Time  {:.2}s",
        label(&passed.to_string(), true),
        label(&failed.to_string(), failed == 0),
        label(&file_errors.to_string(), file_errors == 0),
        elapsed.as_secs_f64(),
    );
}

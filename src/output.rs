use std::io::{self, IsTerminal};
use std::time::Duration;

/// Chunk name of the embedded Lua API. The brackets keep it distinct from any test file path.
pub const API_CHUNK: &str = "=[dnstest]";

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
        for line in error_lines(&error.to_string()) {
            output.push_str(&format!("      {line}\n"));
        }
    }

    output
}

/// Drops traceback frames from the runner's own Lua and native code so failures point at tests.
fn error_lines(error: &str) -> Vec<&str> {
    let lines: Vec<&str> = error.lines().collect();
    let Some(header) = lines.iter().rposition(|line| *line == "stack traceback:") else {
        return lines;
    };

    let frames = &lines[header + 1..];
    let kept: Vec<&str> = frames
        .iter()
        .enumerate()
        .filter(|&(index, frame)| {
            // Native frames such as `error` or a coroutine poll belong to the internal frame
            // that called them. Others, such as `table.sort`, give context to user frames.
            let native_for_internal = frame.trim_start().starts_with("[C]:")
                && frames
                    .get(index + 1)
                    .is_some_and(|next| internal_frame(next));
            !internal_frame(frame) && !native_for_internal
        })
        .map(|(_, frame)| *frame)
        .collect();

    let mut result = lines[..header].to_vec();
    if !kept.is_empty() {
        result.push(lines[header]);
        result.extend(kept);
    }

    result
}

fn internal_frame(line: &str) -> bool {
    let frame = line.trim_start();
    frame.starts_with(&format!("{}:", &API_CHUNK[1..])) || frame.starts_with("__mlua_async_poll:")
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

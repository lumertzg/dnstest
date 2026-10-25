# Development

- Use the mise-managed Rust nightly toolchain.
- Run `mise exec -- cargo fmt --check`, `mise exec -- cargo clippy --all-targets -- -D warnings`, and `mise exec -- cargo test` before finishing code changes.
- Use the project-pinned Lua 5.4, StyLua, and Lua Language Server through mise.
- For Lua changes, run `mise exec -- stylua --check src/api.lua tests examples` and `mise exec -- cargo run --locked -- tests`.

# Style

- Keep the implementation small and separate CLI parsing, DNS queries, Lua execution, and terminal output.
- Use a single blank line between logical steps within functions.
- Comments should explain why, not what.

// Attribute-macro registration: Rust's decorator equivalent
#[tool(name = "rust_echo", description = "Echoes text back unchanged")]
fn echo(text: String) -> String {
    text
}

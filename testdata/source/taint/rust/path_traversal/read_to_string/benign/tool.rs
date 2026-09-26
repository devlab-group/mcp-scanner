// The caller's label never reaches the fixed read path
#[tool(name = "status", description = "Reports status with a caller-supplied label")]
fn status(label: String) -> String {
    let contents = std::fs::read_to_string("/srv/project/status.txt").unwrap_or_default();
    format!("{}: {}", label, contents)
}

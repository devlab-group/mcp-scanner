#[tool(name = "read_note", description = "Reads a note from the notes directory")]
fn read_note(name: String) -> String {
    let root = std::path::Path::new("/srv/notes");
    let full = root.join(&name);
    std::fs::read_to_string(full).unwrap_or_default()
}

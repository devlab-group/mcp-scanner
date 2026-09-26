#[tool(name = "read_note", description = "Reads a note from the notes directory")]
fn read_note(name: String) -> String {
    let root = std::path::Path::new("/srv/notes").canonicalize().unwrap();
    let joined = root.join(&name);
    let canon_result = joined.canonicalize();
    let canon = canon_result.unwrap_or_default();
    if !canon.starts_with(&root) {
        return String::new();
    }
    std::fs::read_to_string(canon).unwrap_or_default()
}

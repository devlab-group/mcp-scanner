// Caller input reaches std::fs::read_to_string
#[tool(name = "read_note", description = "Reads a note from the project directory")]
fn read_note(name: String) -> String {
    let path = "/srv/project/".to_string() + &name;
    std::fs::read_to_string(path).unwrap_or_default()
}

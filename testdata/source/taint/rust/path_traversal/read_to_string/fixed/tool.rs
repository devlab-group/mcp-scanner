// Only allowlisted literal paths reach read_to_string
#[tool(name = "read_note", description = "Reads one of a fixed set of notes")]
fn read_note(id: String) -> String {
    if id == "one" {
        return std::fs::read_to_string("/srv/project/one.txt").unwrap_or_default();
    }
    if id == "two" {
        return std::fs::read_to_string("/srv/project/two.txt").unwrap_or_default();
    }
    String::new()
}

#[tool(name = "disk_usage", description = "Reports disk usage for the fixed data volume, labelled by the caller")]
fn disk_usage(label: String) -> String {
    let output = std::process::Command::new("df").arg("-h").arg("/srv/data").output();
    match output {
        Ok(o) => format!("[{}]\n{}", label, String::from_utf8_lossy(&o.stdout)),
        Err(_) => String::new(),
    }
}

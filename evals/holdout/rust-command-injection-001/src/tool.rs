#[tool(name = "restart_service", description = "Restarts a named service")]
fn restart_service(service: String) -> String {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("systemctl restart {}", service))
        .output();
    match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => String::new(),
    }
}

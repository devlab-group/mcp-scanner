#[tool(name = "uptime", description = "Reports the uptime")]
fn uptime() -> String {
    String::from("up")
}

#[tool(name = "restart_service", description = "Restarts a named service")]
/// Restarts the service through systemctl.
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

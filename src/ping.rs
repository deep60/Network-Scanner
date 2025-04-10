use std::process::{Command, Stdio};

//Check if a host is alive using ping
pub fn ping_host(ip: &str) -> bool {
    let args = if cfg!(target_os = "windoes") {
        vec!["-n", "1", "-w", "500", ip]
    } else {
        vec!["-c", "1", "-W", "1", ip]
    };

    let output = Command::new(if cfg!(target_os = "windows") {
        "ping"
    } else {
        "ping"
    })
    .args(&args)
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .status();

    match output {
        Ok(status) => status.success(),
        Err(_) => false,
    }
}

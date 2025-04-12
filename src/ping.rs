use std::process::{Command as ProcessCommand};

//Check if a host is alive using ping
pub fn ping_host(host: &str) -> bool {
    let args = if cfg!(target_os = "windows") {
        vec!["-n", "1", "-w", "1000", host]
    } else {
        vec!["-c", "1", "-W", "1", host]
    };

    let output = ProcessCommand::new("ping").args(&args).output();

    match output {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

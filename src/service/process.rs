use std::io::{self, Write};
use std::process::{Command, Stdio};
#[cfg(not(target_os = "windows"))]
use std::process::Output;

pub fn spawn_process(command: &str, args: &[&str], mut log: std::fs::File) -> io::Result<u32> {
    // Log the command being executed
    let _ = writeln!(log, "Spawning process: {} {}", command, args.join(" "));
    log.flush()?;

    #[cfg(target_os = "macos")]
    {
        // On macOS, use posix_spawn via Command
        let child = Command::new(command)
            .args(args)
            .stdout(Stdio::from(log))
            .stderr(Stdio::null())
            .spawn()?;
        
        // Get the process ID
        let pid = child.id();
        
        // Detach the child process
        std::thread::spawn(move || {
            let _ = child.wait_with_output();
        });
        
        Ok(pid)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let child = Command::new(command)
            .args(args)
            .stdout(log)
            .stderr(Stdio::null())
            .spawn()?;
        Ok(child.id())
    }
}

#[cfg(target_os = "windows")]
pub fn kill_process(pid: u32) -> io::Result<()> {
    let taskkill_args = &["/F", "/PID", &pid.to_string()];
    Command::new("taskkill")
        .args(taskkill_args)
        .output()?;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn kill_process(pid: u32) -> io::Result<()> {
    let kill_args = &["-9", &pid.to_string()];
    let output: Output = Command::new("kill")
        .args(kill_args)
        .output()?;

    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::Other, format!("Kill command failed: {:?}", output)))
    }
}
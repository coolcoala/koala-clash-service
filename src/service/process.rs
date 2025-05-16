#[cfg(not(target_os = "windows"))]
use std::process::Output;
use std::{
    io::{self, Write},
    process::{Command, Stdio},
};

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

pub fn spawn_process_debug(command: &str, args: &[&str]) -> io::Result<(u32, String, i32)> {
    let child = Command::new(command)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let pid = child.id();
    let output = child.wait_with_output()?;

    // Combine stdout and stderr
    let mut combined_output = String::new();
    if !output.stdout.is_empty() {
        combined_output.push_str(&String::from_utf8_lossy(&output.stdout));
    }
    if !output.stderr.is_empty() {
        if !combined_output.is_empty() {
            combined_output.push('\n');
        }
        combined_output.push_str(&String::from_utf8_lossy(&output.stderr));
    }

    // Get the exit code
    let exit_code = output.status.code().unwrap_or(-1);

    Ok((pid, combined_output, exit_code))
}

#[cfg(target_os = "windows")]
pub fn kill_process(pid: u32) -> io::Result<()> {
    let taskkill_args = &["/PID", &pid.to_string()];
    Command::new("taskkill").args(taskkill_args).output()?;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn kill_process(pid: u32) -> io::Result<()> {
    let kill_args = &["-2", &pid.to_string()];
    let output: Output = Command::new("kill").args(kill_args).output()?;

    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Kill command failed: {:?}", output),
        ))
    }
}

#[cfg(target_os = "windows")]
pub fn find_processes(process_name: &str) -> io::Result<Vec<u32>> {
    let output = Command::new("tasklist")
        .args(&["/FO", "CSV", "/NH"])
        .output()?;
    
    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut pids = Vec::new();
    
    for line in output_str.lines() {
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() >= 2 {
            let name = parts[0].trim_matches('"');
            if name.to_lowercase().contains(&process_name.to_lowercase()) {
                if let Some(pid_str) = parts[1].trim_matches('"').split_whitespace().next() {
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        pids.push(pid);
                    }
                }
            }
        }
    }
    
    Ok(pids)
}

#[cfg(target_os = "linux")]
pub fn find_processes(process_name: &str) -> io::Result<Vec<u32>> {
    let output = Command::new("pgrep")
        .arg("-f")
        .arg(process_name)
        .output()?;
    
    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut pids = Vec::new();
    
    for line in output_str.lines() {
        if let Ok(pid) = line.trim().parse::<u32>() {
            pids.push(pid);
        }
    }
    
    Ok(pids)
}

#[cfg(target_os = "macos")]
pub fn find_processes(process_name: &str) -> io::Result<Vec<u32>> {
    let output = Command::new("pgrep")
        .arg("-f")
        .arg(process_name)
        .output()?;
    
    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut pids = Vec::new();
    
    for line in output_str.lines() {
        if let Ok(pid) = line.trim().parse::<u32>() {
            pids.push(pid);
        }
    }
    
    Ok(pids)
}

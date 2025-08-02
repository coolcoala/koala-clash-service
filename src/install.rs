use std::env;

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn main() {
    panic!("This program is not intended to run on this platform.");
}

#[cfg(not(windows))]
use anyhow::Error;

#[cfg(target_os = "macos")]
fn main() -> Result<(), Error> {
    use koala_clash_service::utils::{run_command, uninstall_old_service};
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;

    let debug = env::args().any(|arg| arg == "--debug");
    let _ = uninstall_old_service();

    let service_binary_path = env::current_exe()
        .unwrap()
        .with_file_name("koala-clash-service");

    if !service_binary_path.exists() {
        return Err(anyhow::anyhow!("koala-clash-service binary not found"));
    }

    // 定义 bundle 路径
    let bundle_path =
        "/Library/PrivilegedHelperTools/io.github.koala-clash.service.bundle";
    let contents_path = format!("{}/Contents", bundle_path);
    let macos_path = format!("{}/MacOS", contents_path);

    // 创建 bundle 目录结构
    std::fs::create_dir_all(&macos_path)
        .map_err(|e| anyhow::anyhow!("Failed to create bundle directories: {}", e))?;

    // 复制二进制文件到 bundle 的 MacOS 目录
    let target_binary_path = format!("{}/koala-clash-service", macos_path);
    std::fs::copy(&service_binary_path, &target_binary_path)
        .map_err(|e| anyhow::anyhow!("Failed to copy service file: {}", e))?;

    // 创建并写入 Info.plist
    let info_plist_path = format!("{}/Info.plist", contents_path);
    let info_plist_content = include_str!("files/info.plist.tmpl");

    std::fs::write(&info_plist_path, info_plist_content)
        .map_err(|e| anyhow::anyhow!("Failed to write Info.plist: {}", e))?;

    // 创建 LaunchDaemons 目录（如果不存在）
    let plist_dir = Path::new("/Library/LaunchDaemons");
    if !plist_dir.exists() {
        std::fs::create_dir(plist_dir)
            .map_err(|e| anyhow::anyhow!("Failed to create plist directory: {}", e))?;
    }

    // 创建并写入 launchd plist
    let plist_file =
        "/Library/LaunchDaemons/io.github.koala-clash.service.plist";
    let plist_file = Path::new(plist_file);

    let launchd_plist_content = include_str!("files/launchd.plist.tmpl");

    File::create(plist_file)
        .and_then(|mut file| file.write_all(launchd_plist_content.as_bytes()))
        .map_err(|e| anyhow::anyhow!("Failed to write plist file: {}", e))?;

    // 设置权限
    // 设置 LaunchDaemons plist 权限
    let _ = run_command("chmod", &["644", plist_file.to_str().unwrap()], debug);
    let _ = run_command(
        "chown",
        &["root:wheel", plist_file.to_str().unwrap()],
        debug,
    );

    // 设置二进制文件权限
    let _ = run_command("chmod", &["544", &target_binary_path], debug);
    let _ = run_command("chown", &["root:wheel", &target_binary_path], debug);

    // 设置 bundle 目录及其内容的权限
    let _ = run_command("chmod", &["755", bundle_path], debug);
    let _ = run_command("chown", &["-R", "root:wheel", bundle_path], debug);

    // 加载和启动服务
    let _ = run_command(
        "launchctl",
        &[
            "enable",
            "system/io.github.koala-clash.service",
        ],
        debug,
    );
    let _ = run_command(
        "launchctl",
        &["bootout", "system", plist_file.to_str().unwrap()],
        debug,
    );
    let _ = run_command(
        "launchctl",
        &["bootstrap", "system", plist_file.to_str().unwrap()],
        debug,
    );
    let _ = run_command(
        "launchctl",
        &["start", "io.github.koala-clash.service"],
        debug,
    );

    Ok(())
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), Error> {
    const SERVICE_NAME: &str = "koala-clash-service";
    use koala_clash_service::utils::run_command;
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;

    let debug = env::args().any(|arg| arg == "--debug");

    let service_binary_path = env::current_exe()
        .unwrap()
        .with_file_name("koala-clash-service");

    if !service_binary_path.exists() {
        return Err(anyhow::anyhow!("koala-clash-service binary not found"));
    }

    // Check service status
    let status_output = std::process::Command::new("systemctl")
        .args(&["status", &format!("{}.service", SERVICE_NAME), "--no-pager"])
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to check service status: {}", e))?;

    match status_output.status.code() {
        Some(0) => return Ok(()), // Service is running
        Some(1) | Some(2) | Some(3) => {
            let _ = run_command(
                "systemctl",
                &["start", &format!("{}.service", SERVICE_NAME)],
                debug,
            )?;
            return Ok(());
        }
        Some(4) => {} // Service not found, continue with installation
        _ => return Err(anyhow::anyhow!("Unexpected systemctl status code")),
    }

    // Create and write unit file
    let unit_file = format!("/etc/systemd/system/{}.service", SERVICE_NAME);
    let unit_file = Path::new(&unit_file);

    let unit_file_content = format!(
        include_str!("files/systemd_service_unit.tmpl"),
        service_binary_path.to_str().unwrap()
    );

    File::create(unit_file)
        .and_then(|mut file| file.write_all(unit_file_content.as_bytes()))
        .map_err(|e| anyhow::anyhow!("Failed to write unit file: {}", e))?;

    // Reload and start service
    let _ = run_command("systemctl", &["daemon-reload"], debug);
    let _ = run_command("systemctl", &["enable", SERVICE_NAME, "--now"], debug);

    Ok(())
}

/// install and start the service
#[cfg(windows)]
fn main() -> windows_service::Result<()> {
    use std::ffi::{OsStr, OsString};
    use windows_service::{
        service::{
            ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState,
            ServiceType,
        },
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;

    let service_access = ServiceAccess::QUERY_STATUS | ServiceAccess::START;
    if let Ok(service) = service_manager.open_service("koala_clash_service", service_access) {
        if let Ok(status) = service.query_status() {
            match status.current_state {
                ServiceState::StopPending
                | ServiceState::Stopped
                | ServiceState::PausePending
                | ServiceState::Paused => {
                    service.start(&Vec::<&OsStr>::new())?;
                }
                _ => {}
            };

            return Ok(());
        }
    }

    let service_binary_path = env::current_exe()
        .unwrap()
        .with_file_name("koala-clash-service.exe");

    if !service_binary_path.exists() {
        eprintln!("koala-clash-service.exe not found");
        std::process::exit(2);
    }

    let service_info = ServiceInfo {
        name: OsString::from("koala_clash_service"),
        display_name: OsString::from("Koala Clash Service"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: service_binary_path,
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None, // run as System
        account_password: None,
    };

    let start_access = ServiceAccess::CHANGE_CONFIG | ServiceAccess::START;
    let service = service_manager.create_service(&service_info, start_access)?;

    service.set_description("Koala Clash Service helps to launch clash core")?;
    service.start(&Vec::<&OsStr>::new())?;

    Ok(())
}

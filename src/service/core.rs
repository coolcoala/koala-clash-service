use super::{
    data::{ClashStatus, CoreManager, MihomoStatus, StartBody, StatusInner, VersionResponse},
    process,
};
use anyhow::{anyhow, Context, Result};
use once_cell::sync::Lazy;
use std::sync::{atomic::Ordering, Arc, Mutex};

impl CoreManager {
    pub fn new() -> Self {
        CoreManager {
            clash_status: StatusInner::new(ClashStatus::default()),
            mihomo_status: StatusInner::new(MihomoStatus::default()),
        }
    }

    pub fn test_config_file(&self) -> Result<(), String> {
        let config = match self
            .clash_status
            .inner
            .lock()
            .unwrap()
            .runtime_config
            .lock()
            .unwrap()
            .clone()
        {
            Some(config) => config,
            None => return Err("Runtime config is not set".to_string()),
        };

        let bin_path = config.bin_path.as_str();
        let config_dir = config.config_dir.as_str();
        let config_file = config.config_file.as_str();
        let args = vec!["-d", config_dir, "-f", config_file, "-t"];

        println!(
            "Testing config file with bin_path: {}, config_dir: {}, config_file: {}",
            bin_path, config_dir, config_file
        );

        let result = process::spawn_process_debug(bin_path, &args)
            .map_err(|e| format!("Failed to execute config test: {}", e))?;

        let (_pid, output, _exit_code) = result;

        let mut errors: Vec<String> = Vec::new();
        for line in output.lines() {
            if line.contains("fata") || line.contains("error") {
                if let Some(pos) = line.find("msg=") {
                    if pos + 1 < line.len() {
                        let message = line[(pos + 4)..].trim().replace("'", "").replace('"', "");
                        let prefix = "[broken]";
                        errors.push(format!("{} {}", prefix, message));
                    }
                }
            }
        }

        if !errors.is_empty() {
            return Err(errors.join("\n"));
        }

        println!("Config test passed successfully");
        Ok(())
    }
}

impl CoreManager {
    pub fn get_version(&self) -> Result<VersionResponse> {
        let current_pid = std::process::id() as i32;
        println!("Current PID: {}", current_pid);
        
        Ok(VersionResponse {
            service: "Clash Verge Service".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        })
    }

    pub fn get_clash_status(&self) -> Result<StartBody> {
        let runtime_config = self
            .clash_status
            .inner
            .lock()
            .unwrap()
            .runtime_config
            .lock()
            .unwrap()
            .clone();
        if runtime_config.is_none() {
            return Ok(StartBody::default());
        }
        Ok(runtime_config.as_ref().unwrap().clone())
    }

    pub fn start_mihomo(&self) -> Result<()> {
        println!("Starting mihomo with config");

        {
            let is_running_mihomo = self
                .mihomo_status
                .inner
                .lock()
                .unwrap()
                .is_running
                .load(Ordering::Relaxed);
            let mihomo_running_pid = self
                .mihomo_status
                .inner
                .lock()
                .unwrap()
                .running_pid
                .load(Ordering::Relaxed);

            if is_running_mihomo && mihomo_running_pid > 0 {
                println!("Mihomo is already running, stopping it first");
                let _ = self.stop_mihomo();
                println!("Mihomo stopped successfully");
            }
        }

        // 检测并停止系统中其他可能运行的verge-mihomo进程
        self.stop_other_mihomo_processes()?;

        {
            // Get runtime config
            let config = self
                .clash_status
                .inner
                .lock()
                .unwrap()
                .runtime_config
                .lock()
                .unwrap()
                .clone();
            let config = config.ok_or(anyhow!("Runtime config is not set"))?;

            let bin_path = config.bin_path.as_str();
            let config_dir = config.config_dir.as_str();
            let config_file = config.config_file.as_str();
            let log_file = config.log_file.as_str();
            let args = vec!["-d", config_dir, "-f", config_file];

            println!(
                "Starting mihomo with bin_path: {}, config_dir: {}, config_file: {}, log_file: {}",
                bin_path, config_dir, config_file, log_file
            );

            // Open log file
            let log = std::fs::File::create(log_file)
                .with_context(|| format!("Failed to open log file: {}", log_file))?;

            // Spawn process
            let pid = process::spawn_process(bin_path, &args, log)?;
            println!("Mihomo started with PID: {}", pid);

            // Update mihomo status
            self.mihomo_status
                .inner
                .lock()
                .unwrap()
                .running_pid
                .store(pid as i32, Ordering::Relaxed);
            self.mihomo_status
                .inner
                .lock()
                .unwrap()
                .is_running
                .store(true, Ordering::Relaxed);
            println!("Mihomo started successfully with PID: {}", pid);
        }

        Ok(())
    }

    pub fn stop_mihomo(&self) -> Result<()> {
        let mihomo_pid = self
            .mihomo_status
            .inner
            .lock()
            .unwrap()
            .running_pid
            .load(Ordering::Relaxed);
        if mihomo_pid <= 0 {
            println!("No running mihomo process found");
            return Ok(());
        }
        println!("Stopping mihomo process {}", mihomo_pid);

        let result = super::process::kill_process(mihomo_pid as u32)
            .with_context(|| format!("Failed to kill mihomo process with PID: {}", mihomo_pid));

        match result {
            Ok(_) => {
                println!("Mihomo process {} stopped successfully", mihomo_pid);
            }
            Err(e) => {
                eprintln!("Error killing mihomo process: {}", e);
            }
        }

        self.mihomo_status
            .inner
            .lock()
            .unwrap()
            .running_pid
            .store(-1, Ordering::Relaxed);
        self.mihomo_status
            .inner
            .lock()
            .unwrap()
            .is_running
            .store(false, Ordering::Relaxed);
        Ok(())
    }

    // 检测并停止其他verge-mihomo进程
    pub fn stop_other_mihomo_processes(&self) -> Result<()> {
        // 获取当前进程的PID
        let current_pid = std::process::id();
        let tracked_mihomo_pid = self
            .mihomo_status
            .inner
            .lock()
            .unwrap()
            .running_pid
            .load(Ordering::Relaxed) as u32;
        
        match process::find_processes("verge-mihomo") {
            Ok(pids) => {
                // 直接在迭代过程中过滤和终止
                let kill_count = pids.into_iter()
                    .filter(|&pid| pid != current_pid && (tracked_mihomo_pid <= 0 || pid != tracked_mihomo_pid))
                    .map(|pid| {
                        println!("Found other verge-mihomo process with PID: {}, stopping it", pid);
                        match process::kill_process(pid) {
                            Ok(_) => {
                                println!("Successfully stopped verge-mihomo process {}", pid);
                                true
                            }
                            Err(e) => {
                                eprintln!("Failed to kill verge-mihomo process {}: {}", pid, e);
                                false
                            }
                        }
                    })
                    .filter(|&success| success)
                    .count();
                    
                println!("Successfully stopped {} verge-mihomo processes", kill_count);
            }
            Err(e) => {
                eprintln!("Error finding verge-mihomo processes: {}", e);
            }
        }
        
        Ok(())
    }

    pub fn start_clash(&self, body: StartBody) -> Result<(), String> {
        {
            // Check clash & stop if needed
            let is_running_clash = self
                .clash_status
                .inner
                .lock()
                .unwrap()
                .is_running
                .load(Ordering::Relaxed);
            let clash_running_pid = self
                .clash_status
                .inner
                .lock()
                .unwrap()
                .running_pid
                .load(Ordering::Relaxed);
            let current_pid = std::process::id() as i32;

            if is_running_clash && clash_running_pid == current_pid {
                println!("Clash is already running with pid: {}", current_pid);
            }
            if !is_running_clash && clash_running_pid <= 0 {
                let current_pid = std::process::id() as i32;
                println!("Clash is start running with pid: {}", current_pid);
                self.clash_status
                    .inner
                    .lock()
                    .unwrap()
                    .running_pid
                    .store(current_pid, Ordering::Relaxed);
                self.clash_status
                    .inner
                    .lock()
                    .unwrap()
                    .is_running
                    .store(true, Ordering::Relaxed);
                println!("done");
            }
        }

        {
            println!("Setting clash runtime config with config: {:?}", body);
            self.clash_status.inner.lock().unwrap().runtime_config =
                Arc::new(Mutex::new(Some(body.clone())));
            println!("Testing config file");
            self.test_config_file()?;
        }

        {
            // Check mihomo & stop if needed
            println!("Checking if mihomo is running before start clash");
            let is_mihomo_running = self
                .mihomo_status
                .inner
                .lock()
                .unwrap()
                .is_running
                .load(Ordering::Relaxed);
            let mihomo_running_pid = self
                .mihomo_status
                .inner
                .lock()
                .unwrap()
                .running_pid
                .load(Ordering::Relaxed);

            if is_mihomo_running && mihomo_running_pid > 0 {
                println!("Mihomo is running, stopping it first");
                let _ = self.stop_mihomo();
                let _ = self.start_mihomo();
            } else {
                println!("Mihomo is not running, starting it");
                let _ = self.start_mihomo();
            }
        }

        println!("Clash started successfully");
        Ok(())
    }

    pub fn stop_clash(&self) -> Result<()> {
        let clash_pid = self
            .clash_status
            .inner
            .lock()
            .unwrap()
            .running_pid
            .load(Ordering::Relaxed);
        if clash_pid <= 0 {
            println!("No running clash process found");
            return Ok(());
        }
        println!("Stopping clash process {}", clash_pid);

        if let Err(e) = super::process::kill_process(clash_pid as u32)
            .with_context(|| format!("Failed to kill clash process with PID: {}", clash_pid))
        {
            eprintln!("Error killing clash process: {}", e);
        }

        // 同时停止mihomo进程和其他verge-mihomo进程
        let _ = self.stop_mihomo();
        let _ = self.stop_other_mihomo_processes();

        println!("Clash process {} stopped successfully", clash_pid);
        Ok(())
    }
}

// 全局静态的 CoreManager 实例
pub static COREMANAGER: Lazy<Arc<Mutex<CoreManager>>> =
    Lazy::new(|| Arc::new(Mutex::new(CoreManager::new())));

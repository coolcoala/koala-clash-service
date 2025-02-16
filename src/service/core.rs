use super::data::{
    ClashStatus, CoreManager, MihomoStatus, StartBody, StatusInner,
};
use super::process;
use anyhow::{anyhow, Context, Result};
use once_cell::sync::Lazy;
use std::{
    collections::HashMap,
    sync::{atomic::Ordering, Arc, Mutex},
};

impl CoreManager {
    pub fn new() -> Self {
        CoreManager {
            clash_status: StatusInner::new(ClashStatus::default()),
            mihomo_status: StatusInner::new(MihomoStatus::default()),
        }
    }

    pub fn is_healthy(&self) -> Result<bool> {
        let is_running_clash = self.clash_status.inner.lock().unwrap().is_running.load(Ordering::Relaxed);
        let clash_running_pid = self.clash_status.inner.lock().unwrap().running_pid.load(Ordering::Relaxed);
        let is_running_mihomo = self.mihomo_status.inner.lock().unwrap().is_running.load(Ordering::Relaxed);
        let mihomo_running_pid = self.mihomo_status.inner.lock().unwrap().running_pid.load(Ordering::Relaxed);
        println!(
            "Clash running: {}, clash PID: {}, mihomo running: {}, mihomo PID: {}",
            is_running_clash, clash_running_pid, is_running_mihomo, mihomo_running_pid
        );
        Ok(is_running_clash
            && clash_running_pid > 0
            && is_running_mihomo
            && mihomo_running_pid > 0)
    }

    pub fn get_version(&self) -> Result<HashMap<String, String>> {
        let current_pid = std::process::id() as i32;
        println!("Current PID: {}", current_pid);
        Ok(HashMap::from([
            ("service".into(), "Clash Verge Service".into()),
            ("version".into(), env!("CARGO_PKG_VERSION").into()),
        ]))
    }

    pub fn get_clash_status(&self) -> Result<StartBody> {
        let runtime_config = self.clash_status.inner.lock().unwrap().runtime_config.lock().unwrap().clone();
        if runtime_config.is_none() {
            return Ok(StartBody::default());
        }
        Ok(runtime_config.as_ref().unwrap().clone())
    }

    pub fn start_mihomo(&self) -> Result<()> {
        println!("Starting mihomo with config");

        {
            let is_running_mihomo = self.mihomo_status.inner.lock().unwrap().is_running.load(Ordering::Relaxed);
            let mihomo_running_pid = self.mihomo_status.inner.lock().unwrap().running_pid.load(Ordering::Relaxed);

            if is_running_mihomo && mihomo_running_pid > 0 {
                println!("Mihomo is already running, stopping it first");
                let _ = self.stop_mihomo();
                println!("Mihomo stopped successfully");
            }
        }
        
        {
            // Get runtime config
            let config = self.clash_status.inner.lock().unwrap().runtime_config.lock().unwrap().clone();
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
            self.mihomo_status.inner.lock().unwrap().running_pid.store(pid as i32, Ordering::Relaxed);
            self.mihomo_status.inner.lock().unwrap().is_running.store(true, Ordering::Relaxed);
            println!("Mihomo started successfully with PID: {}", pid);
        }

        Ok(())
    }

    pub fn stop_mihomo(&self) -> Result<()> {
        let mihomo_pid = self.mihomo_status.inner.lock().unwrap().running_pid.load(Ordering::Relaxed);
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
    
        self.mihomo_status.inner.lock().unwrap().running_pid.store(-1, Ordering::Relaxed);
        self.mihomo_status.inner.lock().unwrap().is_running.store(false, Ordering::Relaxed);
        Ok(())
    }

    pub fn start_clash(&self, body: StartBody) -> Result<()> {
        {
            // Check clash & stop if needed
            let is_running_clash = self.clash_status.inner.lock().unwrap().is_running.load(Ordering::Relaxed);
            let clash_running_pid = self.clash_status.inner.lock().unwrap().running_pid.load(Ordering::Relaxed);
            let current_pid = std::process::id() as i32;

            if is_running_clash && clash_running_pid == current_pid {
                println!("Clash is already running with the same PID");
            } else if is_running_clash && clash_running_pid > 0 {
                println!("Clash is running with a different PID, stopping it first");
                self.stop_clash()?;
            } else if !is_running_clash && clash_running_pid < 1 {
                let current_pid = std::process::id() as i32;
                println!("Clash is start running with pid: {}", current_pid);
                self.clash_status.inner.lock().unwrap().running_pid.store(current_pid, Ordering::Relaxed);
                self.clash_status.inner.lock().unwrap().is_running.store(true, Ordering::Relaxed);
                println!("done");
            }
        }

        {
            println!("Setting clash runtime config with config: {:?}", body);
            self.clash_status.inner.lock().unwrap().runtime_config = Arc::new(Mutex::new(Some(body.clone())));
        }

        {
            // Check mihomo & stop if needed
            println!("Checking if mihomo is running before start clash");
            let is_mihomo_running = self.mihomo_status.inner.lock().unwrap().is_running.load(Ordering::Relaxed);
            let mihomo_running_pid = self.mihomo_status.inner.lock().unwrap().running_pid.load(Ordering::Relaxed);

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
        let clash_pid = self.clash_status.inner.lock().unwrap().running_pid.load(Ordering::Relaxed);
        if clash_pid <= 0 {
            println!("No running clash process found");
            return Ok(());
        }
        println!("Stopping clash process {}", clash_pid);
    
        if let Err(e) = super::process::kill_process(clash_pid as u32)
            .with_context(|| format!("Failed to kill clash process with PID: {}", clash_pid)) {
            eprintln!("Error killing clash process: {}", e);
        }
        
        println!("Clash process {} stopped successfully", clash_pid);
        Ok(())
    }
}

// 全局静态的 CoreManager 实例
pub static COREMANAGER: Lazy<Arc<Mutex<CoreManager>>> =
    Lazy::new(|| Arc::new(Mutex::new(CoreManager::new())));

// 在服务启动时调用这个函数
#[cfg(target_os = "linux")]
pub fn init_signal_handler() {
    use nix::sys::signal::{self, SigAction, SigHandler, Signal};
    unsafe {
        // 设置 SIGCHLD 处理函数，自动回收子进程
        let sa = SigAction::new(
            SigHandler::Handler(handle_sigchld),
            signal::SaFlags::empty(),
            signal::SigSet::empty(),
        );
        let _ = signal::sigaction(Signal::SIGCHLD, &sa);
    }
}

#[cfg(target_os = "linux")]
extern "C" fn handle_sigchld(_: i32) {
    unsafe {
        // 循环等待所有已终止的子进程
        while libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) > 0 {}
    }
}

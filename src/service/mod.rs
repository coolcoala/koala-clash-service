mod core;
mod data;
mod process;

use self::data::*;
use tokio::runtime::Runtime;
use warp::Filter;
use std::net::IpAddr;
use std::sync::Arc;
use std::collections::HashSet;
use once_cell::sync::Lazy;
use rand::Rng;
use std::path::PathBuf;
use std::fs;

#[cfg(target_os = "macos")]
use clash_verge_service::utils;
use core::COREMANAGER;
#[cfg(windows)]
use std::{ffi::OsString, time::Duration};
#[cfg(windows)]
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher, Result,
};

#[cfg(windows)]
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
#[cfg(not(target_os = "macos"))]
const SERVICE_NAME: &str = "clash_verge_service";
const LISTEN_PORT: u16 = 33211;

// 密钥文件路径
const API_KEY_FILE: &str = "clash_verge_api.key";

// 生成随机密钥
fn generate_api_key() -> String {
    let mut rng = rand::thread_rng();
    let key: String = (0..32)
        .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
        .collect();
    key
}

// 读取或生成API密钥
fn get_or_create_api_key() -> String {
    let key_path = PathBuf::from(API_KEY_FILE);
    
    // 生成新密钥并写入文件
    let key = generate_api_key();
    if let Err(e) = fs::write(&key_path, &key) {
        eprintln!("Failed to write API key file: {}", e);
    }
    key
}

// 配置API密钥和允许的IP地址
static API_KEY: Lazy<String> = Lazy::new(|| {
    // 优先使用环境变量中的密钥
    if let Ok(key) = std::env::var("CLASH_VERGE_API_KEY") {
        return key;
    }
    // 否则使用文件中的密钥
    get_or_create_api_key()
});

static ALLOWED_IPS: Lazy<Arc<HashSet<IpAddr>>> = Lazy::new(|| {
    let mut ips = HashSet::new();
    // 默认只允许本地访问
    ips.insert("127.0.0.1".parse().unwrap());
    Arc::new(ips)
});

// API密钥验证过滤器
fn with_api_key() -> impl Filter<Extract = (), Error = warp::Rejection> + Clone {
    warp::header::<String>("X-API-Key")
        .and_then(|key: String| async move {
            if key == *API_KEY {
                Ok(())
            } else {
                Err(warp::reject::custom(ApiKeyError))
            }
        })
        .untuple_one()
}

// IP白名单过滤器
fn with_ip_whitelist() -> impl Filter<Extract = (), Error = warp::Rejection> + Clone {
    warp::addr::remote()
        .and_then(|addr: Option<std::net::SocketAddr>| async move {
            if let Some(addr) = addr {
                if ALLOWED_IPS.contains(&addr.ip()) {
                    return Ok(());
                }
            }
            Err(warp::reject::custom(IpWhitelistError))
        })
        .untuple_one()
}

// 自定义错误类型
#[derive(Debug)]
struct ApiKeyError;
impl warp::reject::Reject for ApiKeyError {}

#[derive(Debug)]
struct IpWhitelistError;
impl warp::reject::Reject for IpWhitelistError {}

macro_rules! wrap_response {
    ($expr: expr) => {
        match $expr {
            Ok(data) => warp::reply::json(&JsonResponse {
                code: 0,
                msg: "ok".into(),
                data: Some(data),
            }),
            Err(err) => warp::reply::json(&JsonResponse {
                code: 400,
                msg: format!("{err}"),
                data: Option::<()>::None,
            }),
        }
    };
}

/// The Service
pub async fn run_service() -> anyhow::Result<()> {
    // 打印API密钥信息
    println!("API Key: {}", *API_KEY);
    println!("API Key file path: {}", API_KEY_FILE);

    // 开启服务 设置服务状态
    #[cfg(windows)]
    let status_handle = service_control_handler::register(
        SERVICE_NAME,
        move |event| -> ServiceControlHandlerResult {
            match event {
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                ServiceControl::Stop => std::process::exit(0),
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        },
    )?;
    #[cfg(windows)]
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    let api_get_version = warp::get()
        .and(warp::path("version"))
        .and(with_api_key())
        .and(with_ip_whitelist())
        .map(move || wrap_response!(COREMANAGER.lock().unwrap().get_version()));

    let api_start_clash = warp::post()
        .and(warp::path("start_clash"))
        .and(with_api_key())
        .and(with_ip_whitelist())
        .and(warp::body::json())
        .map(move |body: StartBody| wrap_response!(COREMANAGER.lock().unwrap().start_clash(body)));

    let api_stop_clash = warp::post()
        .and(warp::path("stop_clash"))
        .and(with_api_key())
        .and(with_ip_whitelist())
        .map(move || wrap_response!(COREMANAGER.lock().unwrap().stop_mihomo()));

    let api_get_clash = warp::get()
        .and(warp::path("get_clash"))
        .and(with_api_key())
        .and(with_ip_whitelist())
        .map(move || wrap_response!(COREMANAGER.lock().unwrap().get_clash_status()));

    let api_stop_service = warp::post()
        .and(warp::path("stop_service"))
        .and(with_api_key())
        .and(with_ip_whitelist())
        .map(|| wrap_response!(stop_service()));

    let api_exit_sys = warp::post()
        .and(warp::path("exit_sys"))
        .and(with_api_key())
        .and(with_ip_whitelist())
        .map(move || wrap_response!(COREMANAGER.lock().unwrap().stop_clash()));

    warp::serve(
        api_get_version
            .or(api_start_clash)
            .or(api_stop_clash)
            .or(api_stop_service)
            .or(api_get_clash)
            .or(api_exit_sys),
    )
    .run(([127, 0, 0, 1], LISTEN_PORT))
    .await;

    Ok(())
}

// 停止服务
#[cfg(target_os = "windows")]
fn stop_service() -> Result<()> {
    let status_handle =
        service_control_handler::register(SERVICE_NAME, |_| ServiceControlHandlerResult::NoError)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}
#[cfg(target_os = "linux")]
fn stop_service() -> anyhow::Result<()> {
    // systemctl stop clash_verge_service
    std::process::Command::new("systemctl")
        .arg("stop")
        .arg(SERVICE_NAME)
        .output()
        .expect("failed to execute process");
    Ok(())
}

#[cfg(target_os = "macos")]
fn stop_service() -> anyhow::Result<()> {
    // launchctl stop clash_verge_service
    let _ = utils::run_command(
        "launchctl",
        &["stop", "io.github.clash-verge-rev.clash-verge-rev.service"],
        true,
    );

    Ok(())
}

/// Service Main function
#[cfg(windows)]
pub fn main() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

#[cfg(not(windows))]
pub fn main() {
    if let Ok(rt) = Runtime::new() {
        rt.block_on(async {
            let _ = run_service().await;
        });
    }
}

#[cfg(windows)]
define_windows_service!(ffi_service_main, my_service_main);

#[cfg(windows)]
pub fn my_service_main(_arguments: Vec<OsString>) {
    if let Ok(rt) = Runtime::new() {
        rt.block_on(async {
            let _ = run_service().await;
        });
    }
}

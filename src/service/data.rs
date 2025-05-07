use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicBool, AtomicI32},
    Arc, Mutex,
};

#[derive(Default, Debug, Deserialize, Serialize, Clone)]
pub struct StartBody {
    pub core_type: Option<String>,
    pub bin_path: String,
    pub config_dir: String,
    pub config_file: String,
    pub log_file: String,
}

#[derive(Deserialize, Serialize)]
pub struct JsonResponse<T: Serialize> {
    pub code: u64,
    pub msg: String,
    pub data: Option<T>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct VersionResponse {
    pub service: String,
    pub version: String,
}

#[derive(Default, Debug)]
pub struct ClashStatus {
    pub is_running: Arc<AtomicBool>,
    pub running_pid: Arc<AtomicI32>,
    pub runtime_config: Arc<Mutex<Option<StartBody>>>,
}

#[derive(Default, Debug)]
pub struct MihomoStatus {
    pub is_running: Arc<AtomicBool>,
    pub running_pid: Arc<AtomicI32>,
}

pub struct CoreManager {
    pub clash_status: StatusInner<ClashStatus>,
    pub mihomo_status: StatusInner<MihomoStatus>,
}

pub struct StatusInner<T> {
    pub inner: Arc<Mutex<T>>,
}

impl<T> StatusInner<T> {
    pub fn new(inner: T) -> Self {
        StatusInner {
            inner: Arc::new(Mutex::new(inner)),
        }
    }
}

use std::{process::Command, string::String};

#[cfg(target_os = "macos")]
pub fn verify_binary_signature(binary_path: &str) -> bool {
    // 执行 codesign 命令获取签名信息
    let output = match Command::new("codesign")
        .args(&["-dv", "--verbose=4", binary_path])
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            eprintln!("Failed to execute codesign: {}", e);
            return false;
        }
    };

    // 注意：codesign 的详细输出在 stderr 而不是 stdout
    let output_str = String::from_utf8_lossy(&output.stderr); // 改为 stderr
    println!("codesign output: {:?}", output_str);

    // 1. 检查 Identifier
    let valid_identifiers = ["verge-mihomo-alpha", "verge-mihomo"];
    if !valid_identifiers
        .iter()
        .any(|id| output_str.contains(&format!("Identifier={}", id)))
    {
        eprintln!("Identifier verification failed");
        return false;
    }

    // 2. 检查 TeamIdentifier
    if !output_str.contains("TeamIdentifier=JPH3Z7PPBB") {
        eprintln!("TeamIdentifier verification failed");
        return false;
    }

    // 3. 检查 Authority 链
    let required_authorities = [
        "Authority=Developer ID Application: won fen (JPH3Z7PPBB)",
        "Authority=Developer ID Certification Authority",
        "Authority=Apple Root CA",
    ];

    for authority in required_authorities.iter() {
        if !output_str.contains(authority) {
            eprintln!("Authority verification failed for: {}", authority);
            return false;
        }
    }

    // 4. 额外验证：检查签名是否有效
    match Command::new("codesign")
        .args(&["--verify", "--verbose", binary_path])
        .status()
    {
        Ok(status) if status.success() => true,
        _ => {
            eprintln!("Signature verification failed");
            false
        }
    }
}

// TODO
#[cfg(target_os = "linux")]
pub fn verify_binary_signature(binary_path: &str) -> bool {
    true
}

// TODO
#[cfg(target_os = "windows")]
pub fn verify_binary_signature(binary_path: &str) -> bool {
    true
}

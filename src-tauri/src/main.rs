#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::Command;
use std::sync::Mutex;
use std::fs::{OpenOptions, self};
use std::io::Write;
use std::collections::HashMap;
use sysinfo::{System, SystemExt, ProcessExt, NetworkExt, PidExt};
use tauri::{State, SystemTray, SystemTrayMenu, SystemTrayEvent, CustomMenuItem, Manager};

// --- Structs ---

#[derive(serde::Serialize)]
struct FirewallStatus {
    active: bool,
    profile: String,
    inbound: String,
    outbound: String,
}

#[derive(serde::Serialize)]
struct Rule {
    id: usize,
    action: String,
    to: String,
    from: String,
    comment: String,
}

#[derive(serde::Serialize)]
struct ChildProc {
    pid: u32,
    name: String,
    status: String,
}

#[derive(serde::Serialize)]
struct AppConnection {
    pid: u32,
    name: String,
    remote_ip: String,
    country: String,
    port: u16,
    status: String,
    children: Vec<ChildProc>,
}

#[derive(serde::Serialize)]
struct NetStats {
    rx_kbps: f64,
    tx_kbps: f64,
    total_kbps: f64,
}

struct AppState {
    sys: Mutex<System>,
}

// --- Commands ---

#[tauri::command]
fn get_net_stats(state: State<AppState>) -> NetStats {
    let mut sys = state.sys.lock().unwrap();
    sys.refresh_networks();
    
    let mut rx = 0;
    let mut tx = 0;
    
    for (_name, data) in sys.networks() {
        rx += data.received();
        tx += data.transmitted();
    }
    
    // Convert bytes to KB
    let rx_kb = (rx as f64) / 1024.0;
    let tx_kb = (tx as f64) / 1024.0;

    NetStats { rx_kbps: rx_kb, tx_kbps: tx_kb, total_kbps: rx_kb + tx_kb }
}

#[tauri::command]
fn get_status() -> FirewallStatus {
    let output = Command::new("ufw").arg("status").arg("verbose").output();
    let mut status = FirewallStatus {
        active: false, profile: "Public".into(), inbound: "deny".into(), outbound: "allow".into(),
    };

    if let Ok(o) = output {
        let out = String::from_utf8_lossy(&o.stdout);
        status.active = out.contains("Status: active");
        if out.contains("Default: deny (incoming), deny (outgoing)") { status.profile = "Lockdown".into(); }
        else if out.contains("Default: allow (incoming)") { status.profile = "Private".into(); }
        else { status.profile = "Public".into(); }
    }
    status
}

#[tauri::command]
fn toggle_firewall(enable: bool) -> bool {
    let action = if enable { "enable" } else { "disable" };
    Command::new("ufw").arg(action).status().map(|s| s.success()).unwrap_or(false)
}

#[tauri::command]
fn get_rules() -> Vec<Rule> {
    let output = Command::new("ufw").arg("status").arg("numbered").output();
    let mut rules = Vec::new();
    if let Ok(o) = output {
        for line in String::from_utf8_lossy(&o.stdout).lines() {
            if line.starts_with('[') {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    let id = parts[0].trim_matches(|c| c == '[' || c == ']').parse().unwrap_or(0);
                    rules.push(Rule {
                        id, to: parts[1].to_string(), action: parts[2].to_string(), from: parts[3].to_string(), comment: "".to_string(),
                    });
                }
            }
        }
    }
    rules
}

#[tauri::command]
fn add_rule(port: String, action: String, proto: String) -> bool {
    let target = if proto == "any" { port } else { format!("{}/{}", port, proto) };
    Command::new("ufw").arg(&action).arg(&target).status().map(|s| s.success()).unwrap_or(false)
}

#[tauri::command]
fn delete_rule(id: usize) -> bool {
    Command::new("ufw").arg("--force").arg("delete").arg(id.to_string()).status().map(|s| s.success()).unwrap_or(false)
}

#[tauri::command]
fn set_profile(mode: String) -> bool {
    let (inc, out) = match mode.as_str() {
        "Public" => ("deny", "allow"),
        "Private" => ("allow", "allow"),
        "Lockdown" | "BlockAll" => ("deny", "deny"),
        _ => ("deny", "allow"),
    };
    let s1 = Command::new("ufw").arg("default").arg(inc).arg("incoming").status().is_ok();
    let s2 = Command::new("ufw").arg("default").arg(out).arg("outgoing").status().is_ok();
    s1 && s2
}

#[tauri::command]
fn get_live_conns(state: State<AppState>) -> Vec<AppConnection> {
    let mut conns = Vec::new();
    let output = Command::new("ss").args(&["-tunap"]).output();
    
    if let Ok(o) = output {
        let out = String::from_utf8_lossy(&o.stdout);
        let mut sys = state.sys.lock().unwrap();
        sys.refresh_processes();

        // Optimization: Pre-group children by parent PID
        let mut children_map: HashMap<u32, Vec<ChildProc>> = HashMap::new();
        for (pid, proc) in sys.processes() {
            if let Some(parent) = proc.parent() {
                let p_pid = parent.as_u32();
                children_map.entry(p_pid).or_default().push(ChildProc {
                    pid: pid.as_u32(),
                    name: proc.name().to_string(),
                    status: format!("{:?}", proc.status()),
                });
            }
        }

        for line in out.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                let peer = parts[5];
                let proc_info = parts.get(6).unwrap_or(&"");
                
                if let Some(start) = proc_info.find("pid=") {
                    let rest = &proc_info[start+4..];
                    let end = rest.find(',').unwrap_or(rest.len());
                    let pid_str = &rest[..end];
                    
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        let main_name = sys.process(sysinfo::Pid::from_u32(pid))
                            .map(|p| p.name().to_string()).unwrap_or("Unknown".into());

                        // Efficient lookup
                        let children_list = children_map.remove(&pid).unwrap_or_default();

                        // GeoIP Stub
                        let country = if peer.starts_with("192.168") || peer.starts_with("10.") || peer.starts_with("127.") { 
                            "LAN".to_string() 
                        } else { 
                            "INET".to_string() 
                        };

                        conns.push(AppConnection {
                            pid, name: main_name, remote_ip: peer.to_string(),
                            country, port: 0, status: "Connected".into(), children: children_list,
                        });
                    }
                }
            }
        }
    }
    conns.dedup_by(|a, b| a.pid == b.pid);
    conns.truncate(50);
    conns
}

#[tauri::command]
fn block_ip(ip: String) -> bool {
    Command::new("ufw").arg("deny").arg("from").arg(ip).status().map(|s| s.success()).unwrap_or(false)
}

#[tauri::command]
fn kill_process(pid: u32, state: State<AppState>) -> bool {
    let sys = state.sys.lock().unwrap();
    if let Some(process) = sys.process(sysinfo::Pid::from_u32(pid)) {
        return process.kill();
    }
    false
}

#[tauri::command]
fn log_event(event: String) {
    let _ = OpenOptions::new()
        .create(true)
        .append(true)
        .open("/var/log/glasswall.log")
        .or_else(|_| OpenOptions::new().create(true).append(true).open("glasswall_local.log"))
        .and_then(|mut file| writeln!(file, "{}", event));
}

#[tauri::command]
fn update_hosts_blocklist(domains: Vec<String>) -> bool {
    let hosts_path = "/etc/hosts";
    if let Ok(current_hosts) = fs::read_to_string(hosts_path) {
        let mut new_content = String::new();
        let marker = "### GLASSWALL BLOCKLIST ###";
        
        if let Some(idx) = current_hosts.find(marker) {
            new_content.push_str(&current_hosts[..idx]);
        } else {
            new_content.push_str(&current_hosts);
            if !new_content.ends_with('\n') { new_content.push('\n'); }
        }

        new_content.push_str(marker);
        new_content.push('\n');
        for domain in domains {
            new_content.push_str(&format!("0.0.0.0 {}\n", domain));
        }

        return fs::write(hosts_path, new_content).is_ok();
    }
    false
}

fn main() {
    let mut sys = System::new_all();
    sys.refresh_all();

    let quit = CustomMenuItem::new("quit".to_string(), "Quit GlassWall");
    let toggle = CustomMenuItem::new("toggle".to_string(), "Toggle Firewall");
    let tray_menu = SystemTrayMenu::new().add_item(toggle).add_item(quit);
    let tray = SystemTray::new().with_menu(tray_menu);

    tauri::Builder::default()
        .manage(AppState { sys: Mutex::new(sys) })
        .system_tray(tray)
        .on_system_tray_event(|app, event| match event {
            SystemTrayEvent::MenuItemClick { id, .. } => {
                match id.as_str() {
                    "quit" => { std::process::exit(0); }
                    "toggle" => { println!("Toggle requested via Tray"); }
                    _ => {}
                }
            }
            SystemTrayEvent::LeftClick { .. } => {
                let window = app.get_window("main").unwrap();
                window.show().unwrap();
                window.set_focus().unwrap();
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            get_status, toggle_firewall, get_rules, 
            add_rule, delete_rule, set_profile, 
            get_live_conns, block_ip, kill_process,
            get_net_stats, log_event, update_hosts_blocklist
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

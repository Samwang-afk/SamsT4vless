#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui::{self, Color32, FontData, FontFamily, RichText, Stroke, Vec2};
use std::collections::VecDeque;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

const SERVER: &str = match option_env!("VLESS_SERVER") {
    Some(v) => v,
    None => "",
};
const PORT: &str = match option_env!("VLESS_PORT") {
    Some(v) => v,
    None => "8443",
};
const UUID: &str = match option_env!("VLESS_UUID") {
    Some(v) => v,
    None => "",
};
const SNI: &str = match option_env!("VLESS_SNI") {
    Some(v) => v,
    None => "",
};
const XHTTP_PATH: &str = match option_env!("VLESS_XHTTP_PATH") {
    Some(v) => v,
    None => "",
};
const CONTROLLER_SECRET: &str = "ss-rs-local-traffic";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const MIHOMO_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/mihomo.exe"));
const WINTUN_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/wintun.dll"));

fn main() -> eframe::Result {
    eframe::run_native(
        "SS-RS",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([430.0, 410.0])
                .with_min_inner_size([390.0, 390.0])
                .with_resizable(true),
            centered: true,
            persist_window: false,
            ..Default::default()
        },
        Box::new(|context| Ok(Box::new(TunnelApp::new(context)))),
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Failed,
}

enum WorkerCommand {
    Stop,
}

enum WorkerEvent {
    Log(String),
    Connected,
    Traffic { upload: u64, download: u64 },
    Exited { expected: bool },
    Failed(String),
}

struct Worker {
    commands: Sender<WorkerCommand>,
    events: Receiver<WorkerEvent>,
}

struct ProxyBackup {
    enabled: u32,
}

struct TrafficStore {
    hour_key: String,
    month_key: String,
    hour_bytes: u64,
    month_bytes: u64,
}

impl TrafficStore {
    fn load(path: &Path) -> Self {
        let (hour_key, month_key) = period_keys();
        let mut value = Self {
            hour_key,
            month_key,
            hour_bytes: 0,
            month_bytes: 0,
        };
        if let Ok(text) = fs::read_to_string(path) {
            for line in text.lines() {
                let Some((key, raw)) = line.split_once('=') else {
                    continue;
                };
                match key {
                    "hour_key" => value.hour_key = raw.to_owned(),
                    "month_key" => value.month_key = raw.to_owned(),
                    "hour_bytes" => value.hour_bytes = raw.parse().unwrap_or(0),
                    "month_bytes" => value.month_bytes = raw.parse().unwrap_or(0),
                    _ => {}
                }
            }
        }
        value.roll_periods();
        value
    }

    fn roll_periods(&mut self) {
        let (hour, month) = period_keys();
        if self.hour_key != hour {
            self.hour_key = hour;
            self.hour_bytes = 0;
        }
        if self.month_key != month {
            self.month_key = month;
            self.month_bytes = 0;
        }
    }

    fn add(&mut self, bytes: u64) {
        self.roll_periods();
        self.hour_bytes = self.hour_bytes.saturating_add(bytes);
        self.month_bytes = self.month_bytes.saturating_add(bytes);
    }

    fn save(&self, path: &Path) {
        let text = format!(
            "hour_key={}\nmonth_key={}\nhour_bytes={}\nmonth_bytes={}\n",
            self.hour_key, self.month_key, self.hour_bytes, self.month_bytes
        );
        let _ = fs::write(path, text);
    }
}

struct TunnelApp {
    state: ConnectionState,
    logs: VecDeque<String>,
    error: Option<String>,
    worker: Option<Worker>,
    runtime_dir: PathBuf,
    traffic_path: PathBuf,
    traffic: TrafficStore,
    last_totals: Option<(u64, u64)>,
    last_save: Instant,
    proxy_backup: Option<ProxyBackup>,
}

impl TunnelApp {
    fn new(context: &eframe::CreationContext<'_>) -> Self {
        configure_style(&context.egui_ctx);
        let runtime_dir = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join("SS-RS");
        let traffic_path = runtime_dir.join("traffic.txt");
        Self {
            state: ConnectionState::Disconnected,
            logs: VecDeque::from(["等待连接…".to_owned()]),
            error: None,
            worker: None,
            traffic: TrafficStore::load(&traffic_path),
            runtime_dir,
            traffic_path,
            last_totals: None,
            last_save: Instant::now(),
            proxy_backup: None,
        }
    }

    fn connect(&mut self) {
        self.error = None;
        let (engine, config) = match prepare_runtime(&self.runtime_dir) {
            Ok(value) => value,
            Err(error) => {
                self.fail(error);
                return;
            }
        };
        match disable_system_proxy() {
            Ok(backup) => self.proxy_backup = Some(backup),
            Err(error) => {
                self.fail(error);
                return;
            }
        }
        let (command_tx, command_rx) = mpsc::channel();
        let (event_tx, event_rx) = mpsc::channel();
        thread::spawn(move || run_worker(engine, config, command_rx, event_tx));
        self.worker = Some(Worker {
            commands: command_tx,
            events: event_rx,
        });
        self.state = ConnectionState::Connecting;
        self.last_totals = None;
        self.logs.clear();
        self.push_log("正在建立 XHTTP 隧道…".into());
    }

    fn disconnect(&mut self) {
        if let Some(worker) = &self.worker {
            let _ = worker.commands.send(WorkerCommand::Stop);
            self.state = ConnectionState::Disconnecting;
            self.push_log("正在恢复网络…".into());
        }
    }

    fn poll_worker(&mut self) {
        let events = self
            .worker
            .as_ref()
            .map(|w| w.events.try_iter().collect::<Vec<_>>())
            .unwrap_or_default();
        for event in events {
            match event {
                WorkerEvent::Log(line) => self.push_log(line),
                WorkerEvent::Connected => {
                    self.state = ConnectionState::Connected;
                    self.error = None;
                    self.push_log("隧道创建成功".into());
                    self.push_log(format!("连接：{SERVER}:{PORT} · TLS/{SNI}"));
                    self.push_log("流量已加密并通过 Cloudflare CDN 转发".into());
                }
                WorkerEvent::Traffic { upload, download } => self.record_traffic(upload, download),
                WorkerEvent::Exited { expected } => {
                    self.worker = None;
                    self.restore_proxy();
                    if expected {
                        self.state = ConnectionState::Disconnected;
                        self.push_log("隧道已断开".into());
                    } else {
                        self.fail("代理核心意外退出".into());
                    }
                }
                WorkerEvent::Failed(message) => {
                    self.restore_proxy();
                    self.fail(message);
                }
            }
        }
    }

    fn record_traffic(&mut self, upload: u64, download: u64) {
        if let Some((old_up, old_down)) = self.last_totals {
            let delta = upload
                .saturating_sub(old_up)
                .saturating_add(download.saturating_sub(old_down));
            self.traffic.add(delta);
            if delta > 0 && self.last_save.elapsed() >= Duration::from_secs(5) {
                self.traffic.save(&self.traffic_path);
                self.last_save = Instant::now();
            }
        }
        self.last_totals = Some((upload, download));
    }

    fn fail(&mut self, message: String) {
        self.state = ConnectionState::Failed;
        self.error = Some(message.clone());
        self.push_log(message);
    }

    fn push_log(&mut self, line: String) {
        if !line.trim().is_empty() {
            self.logs.push_back(line);
            while self.logs.len() > 4 {
                self.logs.pop_front();
            }
        }
    }

    fn restore_proxy(&mut self) {
        if let Some(backup) = self.proxy_backup.take() {
            restore_system_proxy(backup);
        }
        self.traffic.save(&self.traffic_path);
    }

    fn stop_and_wait(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = worker.commands.send(WorkerCommand::Stop);
            let _ = worker.events.recv_timeout(Duration::from_secs(4));
        }
        self.restore_proxy();
    }
}

impl eframe::App for TunnelApp {
    fn logic(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_worker();
        self.traffic.roll_periods();
        context.request_repaint_after(Duration::from_millis(200));
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let margin = (ui.available_width() * 0.06).clamp(16.0, 28.0);
        egui::Frame::new()
            .fill(Color32::from_rgb(247, 243, 233))
            .inner_margin(margin)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new("SS / RS")
                                .size(23.0)
                                .strong()
                                .extra_letter_spacing(2.0),
                        );
                        ui.label(
                            RichText::new("XHTTP CDN TUNNEL")
                                .size(10.0)
                                .color(Color32::from_rgb(119, 113, 104)),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::TOP), |ui| {
                        let (label, color) = status(self.state);
                        ui.label(RichText::new(label).size(12.0).color(color));
                    });
                });
                ui.add_space(10.0);
                ui.separator();
                ui.add_space(12.0);
                egui::Grid::new("details")
                    .num_columns(2)
                    .spacing([20.0, 9.0])
                    .show(ui, |ui| {
                        detail(ui, "SERVER", &format!("{SERVER} : {PORT}"));
                        detail(ui, "TLS", SNI);
                        detail(ui, "MODE", "全局 TUN");
                    });
                ui.add_space(12.0);
                let card_width = ((ui.available_width() - 10.0) / 2.0).max(0.0);
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 10.0;
                    traffic_card(ui, "本小时", self.traffic.hour_bytes, card_width);
                    traffic_card(ui, "本月", self.traffic.month_bytes, card_width);
                });
                ui.add_space(12.0);
                let log_height = (ui.available_height() - 75.0).clamp(72.0, 140.0);
                egui::Frame::new()
                    .fill(Color32::from_rgb(242, 238, 228))
                    .stroke(Stroke::new(1.0, Color32::from_rgb(195, 189, 178)))
                    .inner_margin(10.0)
                    .show(ui, |ui| {
                        ui.set_min_height(log_height);
                        for line in &self.logs {
                            ui.label(
                                RichText::new(line)
                                    .monospace()
                                    .size(10.5)
                                    .color(Color32::from_rgb(80, 76, 70)),
                            );
                        }
                    });
                if let Some(error) = &self.error {
                    ui.label(
                        RichText::new(error)
                            .size(10.5)
                            .color(Color32::from_rgb(145, 65, 55)),
                    );
                } else {
                    ui.add_space(15.0);
                }
                ui.add_space((ui.available_height() - 51.0).max(0.0));
                let busy = matches!(
                    self.state,
                    ConnectionState::Connecting | ConnectionState::Disconnecting
                );
                let label = match self.state {
                    ConnectionState::Connected => "断开连接",
                    ConnectionState::Failed => "重试",
                    ConnectionState::Connecting => "正在连接…",
                    ConnectionState::Disconnecting => "正在断开…",
                    ConnectionState::Disconnected => "连接",
                };
                if sketch_button(ui, label, !busy).clicked() {
                    if self.state == ConnectionState::Connected {
                        self.disconnect();
                    } else {
                        self.connect();
                    }
                }
            });
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.stop_and_wait();
    }
}

fn prepare_runtime(dir: &Path) -> Result<(PathBuf, PathBuf), String> {
    if SERVER.is_empty()
        || UUID.is_empty()
        || SNI.is_empty()
        || XHTTP_PATH.is_empty()
        || MIHOMO_BYTES.is_empty()
        || WINTUN_BYTES.is_empty()
    {
        return Err("客户端构建不完整".into());
    }
    fs::create_dir_all(dir).map_err(|e| format!("无法创建运行目录：{e}"))?;
    let engine = dir.join("mihomo.exe");
    let wintun = dir.join("wintun.dll");
    write_embedded(&engine, MIHOMO_BYTES)?;
    write_embedded(&wintun, WINTUN_BYTES)?;
    let config = dir.join("config.yaml");
    fs::write(&config, mihomo_config()).map_err(|e| format!("无法写入配置：{e}"))?;
    Ok((engine, config))
}

fn write_embedded(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if fs::metadata(path).map(|m| m.len()).ok() != Some(bytes.len() as u64) {
        fs::write(path, bytes).map_err(|e| format!("无法释放 {}：{e}", path.display()))?;
    }
    Ok(())
}

fn mihomo_config() -> String {
    format!(
        r#"mixed-port: 39080
allow-lan: false
mode: rule
log-level: info
ipv6: false
external-controller: 127.0.0.1:39097
secret: {secret}
tun:
  enable: true
  stack: gvisor
  auto-route: true
  strict-route: true
  auto-detect-interface: true
  dns-hijack:
    - any:53
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - 1.1.1.1
    - 8.8.8.8
proxies:
  - name: SamsT4vless-CDN
    type: vless
    server: {server}
    port: {port}
    uuid: {uuid}
    network: xhttp
    encryption: ""
    packet-encoding: xudp
    tls: true
    udp: true
    servername: {sni}
    alpn:
      - h2
      - http/1.1
    skip-cert-verify: false
    client-fingerprint: chrome
    xhttp-opts:
      path: {xhttp_path}
      host: {sni}
      mode: auto
      x-padding-bytes: 100-1000
      x-padding-obfs-mode: false
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - SamsT4vless-CDN
rules:
  - MATCH,PROXY
"#,
        secret = CONTROLLER_SECRET,
        server = SERVER,
        port = PORT,
        uuid = UUID,
        sni = SNI,
        xhttp_path = XHTTP_PATH
    )
}

fn run_worker(
    engine: PathBuf,
    config: PathBuf,
    commands: Receiver<WorkerCommand>,
    events: Sender<WorkerEvent>,
) {
    let mut command = Command::new(engine);
    command
        .args(["-f", config.to_string_lossy().as_ref()])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);
    let mut child = match command.spawn() {
        Ok(value) => value,
        Err(error) => {
            let _ = events.send(WorkerEvent::Failed(format!("无法启动代理核心：{error}")));
            return;
        }
    };
    for stream in [
        child.stdout.take().map(Stream::Out),
        child.stderr.take().map(Stream::Err),
    ]
    .into_iter()
    .flatten()
    {
        let tx = events.clone();
        thread::spawn(move || read_logs(stream, tx));
    }
    supervise_child(&mut child, commands, events);
}

enum Stream {
    Out(std::process::ChildStdout),
    Err(std::process::ChildStderr),
}

fn read_logs(mut stream: Stream, events: Sender<WorkerEvent>) {
    let mut bytes = Vec::new();
    match &mut stream {
        Stream::Out(s) => {
            let _ = s.read_to_end(&mut bytes);
        }
        Stream::Err(s) => {
            let _ = s.read_to_end(&mut bytes);
        }
    }
    for line in String::from_utf8_lossy(&bytes).lines().take(20) {
        let _ = events.send(WorkerEvent::Log(line.to_owned()));
    }
}

fn supervise_child(
    child: &mut Child,
    commands: Receiver<WorkerCommand>,
    events: Sender<WorkerEvent>,
) {
    let mut connected = false;
    loop {
        if commands.try_recv().is_ok() {
            let _ = child.kill();
            let _ = child.wait();
            let _ = events.send(WorkerEvent::Exited { expected: true });
            return;
        }
        match child.try_wait() {
            Ok(Some(_)) => {
                let _ = events.send(WorkerEvent::Exited { expected: false });
                return;
            }
            Err(error) => {
                let _ = events.send(WorkerEvent::Failed(format!("无法读取代理状态：{error}")));
                return;
            }
            Ok(None) => {}
        }
        if let Some((upload, download)) = fetch_totals() {
            if !connected {
                connected = true;
                let _ = events.send(WorkerEvent::Connected);
            }
            let _ = events.send(WorkerEvent::Traffic { upload, download });
        }
        thread::sleep(Duration::from_secs(1));
    }
}

fn fetch_totals() -> Option<(u64, u64)> {
    let address: SocketAddr = "127.0.0.1:39097".parse().ok()?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(300)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(300)))
        .ok()?;
    write!(stream, "GET /connections HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {CONTROLLER_SECRET}\r\nConnection: close\r\n\r\n").ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    Some((
        json_u64(&response, "uploadTotal")?,
        json_u64(&response, "downloadTotal")?,
    ))
}

fn json_u64(text: &str, key: &str) -> Option<u64> {
    let tail = text.split_once(&format!("\"{key}\":"))?.1.trim_start();
    tail[..tail
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(tail.len())]
        .parse()
        .ok()
}

fn disable_system_proxy() -> Result<ProxyBackup, String> {
    let enabled = query_proxy_enable().unwrap_or(0);
    let status = hidden_command("reg")
        .args([
            "add",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "/v",
            "ProxyEnable",
            "/t",
            "REG_DWORD",
            "/d",
            "0",
            "/f",
        ])
        .status()
        .map_err(|e| format!("无法关闭旧系统代理：{e}"))?;
    if !status.success() {
        return Err("无法关闭旧系统代理".into());
    }
    notify_proxy_change();
    Ok(ProxyBackup { enabled })
}

fn restore_system_proxy(backup: ProxyBackup) {
    let _ = hidden_command("reg")
        .args([
            "add",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "/v",
            "ProxyEnable",
            "/t",
            "REG_DWORD",
            "/d",
            &backup.enabled.to_string(),
            "/f",
        ])
        .status();
    notify_proxy_change();
}

fn query_proxy_enable() -> Option<u32> {
    let output = hidden_command("reg")
        .args([
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "/v",
            "ProxyEnable",
        ])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let raw = text.split_whitespace().last()?;
    u32::from_str_radix(raw.trim_start_matches("0x"), 16).ok()
}

fn hidden_command(program: &str) -> Command {
    let mut command = Command::new(program);
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);
    command
}

#[cfg(windows)]
fn notify_proxy_change() {
    #[link(name = "wininet")]
    extern "system" {
        fn InternetSetOptionW(
            handle: *mut std::ffi::c_void,
            option: u32,
            buffer: *mut std::ffi::c_void,
            length: u32,
        ) -> i32;
    }
    unsafe {
        InternetSetOptionW(std::ptr::null_mut(), 39, std::ptr::null_mut(), 0);
        InternetSetOptionW(std::ptr::null_mut(), 37, std::ptr::null_mut(), 0);
    }
}

#[cfg(not(windows))]
fn notify_proxy_change() {}

#[repr(C)]
#[derive(Default)]
struct NativeSystemTime {
    year: u16,
    month: u16,
    day_of_week: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
    millis: u16,
}

#[cfg(windows)]
fn period_keys() -> (String, String) {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetLocalTime(value: *mut NativeSystemTime);
    }
    let mut value = NativeSystemTime::default();
    unsafe {
        GetLocalTime(&mut value);
    }
    (
        format!(
            "{:04}{:02}{:02}{:02}",
            value.year, value.month, value.day, value.hour
        ),
        format!("{:04}{:02}", value.year, value.month),
    )
}

#[cfg(not(windows))]
fn period_keys() -> (String, String) {
    ("hour".into(), "month".into())
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn configure_style(context: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    for path in [r"C:\Windows\Fonts\msyh.ttc", r"C:\Windows\Fonts\simhei.ttf"] {
        if let Ok(bytes) = fs::read(path) {
            fonts
                .font_data
                .insert("system-cjk".into(), FontData::from_owned(bytes).into());
            fonts
                .families
                .entry(FontFamily::Proportional)
                .or_default()
                .insert(0, "system-cjk".into());
            fonts
                .families
                .entry(FontFamily::Monospace)
                .or_default()
                .insert(0, "system-cjk".into());
            break;
        }
    }
    context.set_fonts(fonts);
    let mut visuals = egui::Visuals::light();
    visuals.panel_fill = Color32::from_rgb(247, 243, 233);
    visuals.window_fill = visuals.panel_fill;
    visuals.override_text_color = Some(Color32::from_rgb(41, 40, 36));
    context.set_visuals(visuals);
}

fn detail(ui: &mut egui::Ui, key: &str, value: &str) {
    ui.label(
        RichText::new(key)
            .monospace()
            .size(11.0)
            .color(Color32::from_rgb(138, 132, 122)),
    );
    ui.label(RichText::new(value).monospace().size(12.0));
    ui.end_row();
}

fn traffic_card(ui: &mut egui::Ui, label: &str, bytes: u64, width: f32) {
    egui::Frame::new()
        .stroke(Stroke::new(1.0, Color32::from_rgb(195, 189, 178)))
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.set_width(width - 20.0);
            ui.label(
                RichText::new(label)
                    .size(10.0)
                    .color(Color32::from_rgb(119, 113, 104)),
            );
            ui.label(RichText::new(format_bytes(bytes)).size(18.0).strong());
        });
}

fn sketch_button(ui: &mut egui::Ui, label: &str, enabled: bool) -> egui::Response {
    let (outer_rect, response) = ui.allocate_exact_size(
        Vec2::new(ui.available_width(), 51.0),
        if enabled {
            egui::Sense::click()
        } else {
            egui::Sense::hover()
        },
    );
    let rect = egui::Rect::from_min_max(outer_rect.min, outer_rect.max - Vec2::splat(7.0));
    let hovered = enabled && response.hovered();
    let pressed = enabled && response.is_pointer_button_down_on();
    let (button_offset, shadow_offset) = button_offsets(hovered, pressed);
    let button_rect = rect.translate(Vec2::splat(button_offset));
    let shadow_rect = rect.translate(Vec2::splat(shadow_offset));
    let painter = ui.painter();
    let ink = if enabled {
        Color32::from_rgb(55, 52, 47)
    } else {
        Color32::from_rgb(166, 160, 150)
    };
    let hatch = if hovered {
        Color32::from_rgb(71, 67, 61)
    } else {
        Color32::from_rgb(111, 105, 96)
    };

    painter.rect_stroke(
        shadow_rect,
        0.0,
        Stroke::new(1.0, ink),
        egui::StrokeKind::Inside,
    );
    let clipped = painter.with_clip_rect(shadow_rect);
    let diagonal = shadow_rect.height();
    let mut x = shadow_rect.left() - diagonal;
    while x < shadow_rect.right() {
        clipped.line_segment(
            [
                egui::pos2(x, shadow_rect.bottom()),
                egui::pos2(x + diagonal, shadow_rect.top()),
            ],
            Stroke::new(1.0, hatch),
        );
        x += if hovered { 7.0 } else { 9.0 };
    }

    let fill = if pressed {
        Color32::from_rgb(41, 40, 36)
    } else if hovered {
        Color32::from_rgb(238, 233, 222)
    } else {
        Color32::from_rgb(247, 243, 233)
    };
    painter.rect_filled(button_rect, 0.0, fill);
    painter.rect_stroke(
        button_rect,
        0.0,
        Stroke::new(2.0, ink),
        egui::StrokeKind::Inside,
    );
    painter.text(
        button_rect.center(),
        egui::Align2::CENTER_CENTER,
        label,
        egui::FontId::proportional(14.0),
        if pressed {
            Color32::from_rgb(247, 243, 233)
        } else {
            ink
        },
    );
    response
}

fn button_offsets(hovered: bool, pressed: bool) -> (f32, f32) {
    if pressed {
        (3.0, 4.0)
    } else if hovered {
        (0.0, 7.0)
    } else {
        (0.0, 5.0)
    }
}

fn status(state: ConnectionState) -> (&'static str, Color32) {
    match state {
        ConnectionState::Disconnected => ("● 未连接", Color32::from_rgb(102, 97, 90)),
        ConnectionState::Connecting => ("● 连接中", Color32::from_rgb(130, 105, 65)),
        ConnectionState::Connected => ("● 已连接", Color32::from_rgb(80, 122, 84)),
        ConnectionState::Disconnecting => ("● 正在断开", Color32::from_rgb(130, 105, 65)),
        ConnectionState::Failed => ("× 连接失败", Color32::from_rgb(145, 65, 55)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mihomo_totals() {
        let json = r#"{"downloadTotal":1234,"uploadTotal":56,"connections":[]}"#;
        assert_eq!(json_u64(json, "downloadTotal"), Some(1234));
        assert_eq!(json_u64(json, "uploadTotal"), Some(56));
    }

    #[test]
    fn formats_traffic() {
        assert_eq!(format_bytes(1536), "1.5 KB");
    }

    #[test]
    fn button_shadow_moves_with_pointer_state() {
        assert_eq!(button_offsets(false, false), (0.0, 5.0));
        assert_eq!(button_offsets(true, false), (0.0, 7.0));
        assert_eq!(button_offsets(true, true), (3.0, 4.0));
    }

    #[test]
    fn mihomo_accepts_embedded_config() {
        if MIHOMO_BYTES.is_empty() || UUID.is_empty() {
            return;
        }
        let dir = std::env::temp_dir().join("ss-rs-config-test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let engine = dir.join("mihomo.exe");
        let config = dir.join("config.yaml");
        fs::write(&engine, MIHOMO_BYTES).unwrap();
        fs::write(&config, mihomo_config()).unwrap();
        let status = Command::new(&engine)
            .args(["-t", "-f", config.to_str().unwrap()])
            .status()
            .unwrap();
        let _ = fs::remove_dir_all(&dir);
        assert!(status.success());
    }

    #[test]
    fn live_cdn_proxy() {
        if std::env::var_os("SS_RS_LIVE_TEST").is_none() {
            return;
        }
        let dir = std::env::temp_dir().join("ss-rs-live-test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let engine = dir.join("mihomo.exe");
        let config = dir.join("config.yaml");
        fs::write(&engine, MIHOMO_BYTES).unwrap();
        fs::write(
            &config,
            mihomo_config().replacen("  enable: true", "  enable: false", 1),
        )
        .unwrap();
        let mut child = Command::new(&engine)
            .args(["-f", config.to_str().unwrap()])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        for _ in 0..20 {
            if fetch_totals().is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(250));
        }
        let output = Command::new("curl.exe")
            .args([
                "--silent",
                "--show-error",
                "--max-time",
                "15",
                "--proxy",
                "http://127.0.0.1:39080",
                "https://api.ipify.org",
            ])
            .output()
            .unwrap();
        let totals = fetch_totals();
        let _ = child.kill();
        let logs = child.wait_with_output().unwrap();
        let _ = fs::remove_dir_all(&dir);
        assert!(
            output.status.success(),
            "curl: {}\nmihomo: {}{}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&logs.stdout),
            String::from_utf8_lossy(&logs.stderr)
        );
        if let Ok(expected) = std::env::var("SS_RS_EXPECTED_EXIT_IP") {
            assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), expected);
        } else {
            assert!(!String::from_utf8_lossy(&output.stdout).trim().is_empty());
        }
        assert!(totals.is_some_and(|(up, down)| up + down > 0));
    }
}

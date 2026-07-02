use anyhow::{Context, Result};
use ss_core::{validate_tun_response, Frame, TUN_MODE, TUN_MTU};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[cfg(windows)]
use std::process::Command;
#[cfg(windows)]
use tun::AbstractDevice;

pub async fn run(
    server: &str,
    password: &str,
    dns: Ipv4Addr,
    exit_on_stdin_close: bool,
) -> Result<()> {
    #[cfg(not(windows))]
    {
        let _ = (server, password, dns, exit_on_stdin_close);
        anyhow::bail!("client TUN mode is supported on Windows only");
    }

    #[cfg(windows)]
    run_windows(server, password, dns, exit_on_stdin_close).await
}

#[cfg(windows)]
async fn run_windows(
    server: &str,
    password: &str,
    dns: Ipv4Addr,
    exit_on_stdin_close: bool,
) -> Result<()> {
    let server: SocketAddr = server
        .parse()
        .context("TUN mode requires --server to be an IPv4 address and port")?;
    let server_ip = match server.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => anyhow::bail!("TUN mode requires an IPv4 server address"),
    };

    let (remote, frame) = connect_tun(server, password).await?;
    let mut config = tun::Configuration::default();
    config
        .tun_name("SS-RS")
        .address((10, 8, 0, 2))
        .netmask((255, 255, 255, 252))
        .mtu(TUN_MTU as u16)
        .metric(1)
        .up();
    let dll = std::env::current_exe()?
        .parent()
        .context("client executable has no parent directory")?
        .join("wintun.dll");
    if !dll.is_file() {
        anyhow::bail!("missing {}", dll.display());
    }
    config.platform_config(|platform| {
        platform.wintun_file(dll);
        platform.dns_servers(&[dns.into()]);
    });

    let device = tun::create_as_async(&config)
        .context("failed to create Wintun adapter; run as administrator")?;
    let tun_index = device.tun_index()?;
    let _routes = RouteGuard::install(tun_index, server_ip, dns)?;
    let (mut tun_writer, mut tun_reader) = device.split()?;
    let (mut net_reader, mut net_writer) = remote.into_split();

    tracing::info!("TUN active: all IPv4 traffic via {}, DNS {}", server, dns);
    let upload = async {
        let mut packet = vec![0u8; TUN_MTU];
        loop {
            let n = tun_reader.read(&mut packet).await?;
            if n == 0 {
                anyhow::bail!("Wintun adapter closed");
            }
            if packet[0] >> 4 != 4 {
                continue;
            }
            let encoded = frame.encode(&packet[..n]).map_err(anyhow::Error::msg)?;
            net_writer.write_all(&encoded).await?;
        }
    };
    let download = async {
        loop {
            let packet = read_frame(&mut net_reader, &frame).await?;
            validate_tun_response(&packet).map_err(anyhow::Error::msg)?;
            tun_writer.write_all(&packet).await?;
        }
    };

    tokio::select! {
        result = upload => result,
        result = download => result,
        _ = tokio::signal::ctrl_c() => Ok(()),
        _ = wait_for_gui_stop(exit_on_stdin_close) => Ok(()),
    }
}

async fn wait_for_gui_stop(enabled: bool) {
    if !enabled {
        std::future::pending::<()>().await;
    }
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
    wait_for_stop(&mut stdin).await;
}

async fn wait_for_stop(reader: &mut (impl AsyncBufRead + Unpin)) {
    let mut command = String::new();
    let _ = reader.read_line(&mut command).await;
}

async fn connect_tun(server: SocketAddr, password: &str) -> Result<(TcpStream, Arc<Frame>)> {
    let mut remote = TcpStream::connect(server)
        .await
        .with_context(|| format!("failed to connect to {}", server))?;
    let salt = Frame::generate_salt();
    remote.write_all(&salt).await?;
    let frame = Arc::new(Frame::new(password, &salt));
    remote
        .write_all(&frame.encode(&[TUN_MODE]).map_err(anyhow::Error::msg)?)
        .await?;
    Ok((remote, frame))
}

async fn read_frame(reader: &mut (impl AsyncReadExt + Unpin), frame: &Frame) -> Result<Vec<u8>> {
    let mut header = [0u8; 14];
    reader.read_exact(&mut header).await?;
    let len = u16::from_be_bytes([header[12], header[13]]) as usize;
    let mut full = Vec::with_capacity(14 + len);
    full.extend_from_slice(&header);
    full.resize(14 + len, 0);
    reader.read_exact(&mut full[14..]).await?;
    Ok(frame.decode(&full).map_err(anyhow::Error::msg)?.0)
}

#[cfg(windows)]
struct RouteGuard {
    tun_index: i32,
    physical_index: u32,
    server_ip: Ipv4Addr,
    old_dns: Vec<String>,
}

#[cfg(windows)]
impl RouteGuard {
    fn install(tun_index: i32, server_ip: Ipv4Addr, dns: Ipv4Addr) -> Result<Self> {
        let route = powershell(
            "$r=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1; \"$($r.InterfaceIndex)|$($r.NextHop)\"",
        )?;
        let (physical_index, gateway) = route
            .trim()
            .split_once('|')
            .context("failed to read the physical default route")?;
        let physical_index: u32 = physical_index.parse()?;
        let old_dns = powershell(&format!(
            "(Get-DnsClientServerAddress -InterfaceIndex {} -AddressFamily IPv4).ServerAddresses -join ','",
            physical_index
        ))?
        .trim()
        .split(',')
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect();

        let guard = Self {
            tun_index,
            physical_index,
            server_ip,
            old_dns,
        };
        powershell(&format!(
            "New-NetRoute -PolicyStore ActiveStore -DestinationPrefix '{server_ip}/32' -InterfaceIndex {physical_index} -NextHop '{gateway}' -RouteMetric 1 -ErrorAction Stop | Out-Null; New-NetRoute -PolicyStore ActiveStore -DestinationPrefix '0.0.0.0/1' -InterfaceIndex {tun_index} -NextHop '0.0.0.0' -RouteMetric 1 -ErrorAction Stop | Out-Null; New-NetRoute -PolicyStore ActiveStore -DestinationPrefix '128.0.0.0/1' -InterfaceIndex {tun_index} -NextHop '0.0.0.0' -RouteMetric 1 -ErrorAction Stop | Out-Null; New-NetIPAddress -PolicyStore ActiveStore -InterfaceIndex {tun_index} -IPAddress 'fd00::2' -PrefixLength 126 -ErrorAction SilentlyContinue | Out-Null; New-NetRoute -PolicyStore ActiveStore -DestinationPrefix '::/1' -InterfaceIndex {tun_index} -NextHop '::' -RouteMetric 1 -ErrorAction Stop | Out-Null; New-NetRoute -PolicyStore ActiveStore -DestinationPrefix '8000::/1' -InterfaceIndex {tun_index} -NextHop '::' -RouteMetric 1 -ErrorAction Stop | Out-Null; Set-DnsClientServerAddress -InterfaceIndex {physical_index} -ServerAddresses '{dns}' -ErrorAction Stop"
        ))?;
        Ok(guard)
    }
}

#[cfg(windows)]
impl Drop for RouteGuard {
    fn drop(&mut self) {
        let restore_dns = if self.old_dns.is_empty() {
            format!(
                "Set-DnsClientServerAddress -InterfaceIndex {} -ResetServerAddresses -ErrorAction SilentlyContinue",
                self.physical_index
            )
        } else {
            let addresses = self.old_dns.join("','");
            format!(
                "Set-DnsClientServerAddress -InterfaceIndex {} -ServerAddresses @('{}') -ErrorAction SilentlyContinue",
                self.physical_index, addresses
            )
        };
        let _ = powershell(&format!(
            "Remove-NetRoute -PolicyStore ActiveStore -DestinationPrefix '0.0.0.0/1','128.0.0.0/1','::/1','8000::/1' -InterfaceIndex {} -Confirm:$false -ErrorAction SilentlyContinue; Remove-NetRoute -PolicyStore ActiveStore -DestinationPrefix '{}/32' -InterfaceIndex {} -Confirm:$false -ErrorAction SilentlyContinue; {}",
            self.tun_index, self.server_ip, self.physical_index, restore_dns
        ));
    }
}

#[cfg(windows)]
fn powershell(script: &str) -> Result<String> {
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .context("failed to run PowerShell")?;
    if !output.status.success() {
        anyhow::bail!(
            "PowerShell network configuration failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stop_command_releases_waiter() {
        let (reader, mut writer) = tokio::io::duplex(16);
        let task = tokio::spawn(async move {
            let mut reader = tokio::io::BufReader::new(reader);
            wait_for_stop(&mut reader).await;
        });
        writer.write_all(b"stop\n").await.unwrap();
        task.await.unwrap();
    }
}

use anyhow::{Context, Result};
use clap::Parser;
use ss_core::{pack_addr_payload, Frame, Socks5Addr, MAX_PAYLOAD_LEN};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

mod tun_mode;

#[derive(Parser, Debug)]
#[command(name = "ss-client")]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1:1080")]
    listen: String,

    #[arg(short, long)]
    server: String,

    #[arg(short, long, env = "SS_PASSWORD")]
    password: String,

    #[arg(long, default_value = "127.0.0.1:1081")]
    http_listen: String,

    #[arg(long)]
    tun: bool,

    #[arg(long, default_value = "1.1.1.1")]
    tun_dns: std::net::Ipv4Addr,

    #[arg(long, hide = true)]
    exit_on_stdin_close: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_ansi(false).init();
    let args = Args::parse();

    let listener = TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("failed to bind {}", args.listen))?;
    info!("SOCKS5 proxy on {}", args.listen);

    let http_listener = TcpListener::bind(&args.http_listen)
        .await
        .with_context(|| format!("failed to bind {}", args.http_listen))?;
    info!("HTTP proxy on {}", args.http_listen);

    let server_addr = Arc::new(args.server);
    let password = Arc::new(args.password);

    let s1 = socks5_loop(listener, server_addr.clone(), password.clone());
    let s2 = http_loop(http_listener, server_addr.clone(), password.clone());
    if args.tun {
        tokio::select! {
            result = s1 => result?,
            result = s2 => result?,
            result = tun_mode::run(
                &server_addr,
                &password,
                args.tun_dns,
                args.exit_on_stdin_close,
            ) => result?,
        }
    } else {
        tokio::try_join!(s1, s2)?;
    }
    Ok(())
}

async fn socks5_loop(
    listener: TcpListener,
    server_addr: Arc<String>,
    password: Arc<String>,
) -> Result<()> {
    loop {
        let (stream, addr) = listener.accept().await?;
        let server_addr = server_addr.clone();
        let password = password.clone();
        tokio::spawn(async move {
            let result = handle_socks5(stream, &server_addr, &password).await;
            if let Err(e) = result {
                error!("SOCKS5 {}: {:#}", addr, e);
            }
        });
    }
}

async fn http_loop(
    listener: TcpListener,
    server_addr: Arc<String>,
    password: Arc<String>,
) -> Result<()> {
    loop {
        let (stream, addr) = listener.accept().await?;
        let server_addr = server_addr.clone();
        let password = password.clone();
        tokio::spawn(async move {
            let result = handle_http_connect(stream, &server_addr, &password).await;
            if let Err(e) = result {
                error!("HTTP {}: {:#}", addr, e);
            }
        });
    }
}

async fn connect_to_server(
    server_addr: &str,
    password: &str,
    target: &Socks5Addr,
    first_data: &[u8],
) -> Result<(TcpStream, Arc<Frame>)> {
    let mut remote = TcpStream::connect(server_addr)
        .await
        .with_context(|| format!("failed to connect to {}", server_addr))?;

    let salt = Frame::generate_salt();
    remote.write_all(&salt).await?;
    let frame = Arc::new(Frame::new(password, &salt));
    let first_payload = pack_addr_payload(target, first_data);
    let first_frame = frame
        .encode(&first_payload)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    remote.write_all(&first_frame).await?;
    Ok((remote, frame))
}

async fn relay(local: TcpStream, remote: TcpStream, frame: Arc<Frame>) -> Result<()> {
    let (mut lr, mut lw) = local.into_split();
    let (mut rr, mut rw) = remote.into_split();

    let f1 = frame.clone();
    let upload = tokio::spawn(async move { relay_local_to_remote(&mut lr, &mut rw, &f1).await });

    let f2 = frame.clone();
    let download = tokio::spawn(async move { relay_remote_to_local(&mut rr, &mut lw, &f2).await });

    let (r1, r2) = tokio::join!(upload, download);
    r1??;
    r2??;
    Ok(())
}

async fn handle_socks5(mut local: TcpStream, server_addr: &str, password: &str) -> Result<()> {
    socks5_handshake(&mut local).await?;
    let target = socks5_read_request(&mut local).await?;
    info!("SOCKS5 connect: {:?}", target);

    socks5_respond_success(&mut local).await?;

    let (remote, frame) = connect_to_server(server_addr, password, &target, &[]).await?;
    relay(local, remote, frame).await
}

async fn handle_http_connect(
    mut local: TcpStream,
    server_addr: &str,
    password: &str,
) -> Result<()> {
    let mut buf = vec![0u8; 4096];
    let mut pos = 0;
    loop {
        if pos >= buf.len() {
            anyhow::bail!("request too long");
        }
        let n = local.read(&mut buf[pos..]).await?;
        if n == 0 {
            anyhow::bail!("connection closed during HTTP request");
        }
        pos += n;
        if buf[..pos].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let header = String::from_utf8_lossy(&buf[..pos]);
    let first_line = header.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 3 {
        anyhow::bail!("invalid HTTP request: {}", first_line);
    }

    let method = parts[0];
    let url = parts[1];

    if method == "CONNECT" {
        let (host, port) = url
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("bad CONNECT address: {}", url))?;
        let port: u16 = port
            .parse()
            .with_context(|| format!("bad port: {}", port))?;
        info!("HTTP CONNECT: {}:{}", host, port);

        let target = Socks5Addr::Domain(host.to_string(), port);
        let (remote, frame) = connect_to_server(server_addr, password, &target, &[]).await?;
        local
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        relay(local, remote, frame).await
    } else {
        let (proto, rest) = url
            .split_once("://")
            .ok_or_else(|| anyhow::anyhow!("bad URL: {}", url))?;
        let (host_port, _path) = rest.split_once('/').unwrap_or((rest, ""));
        let (host, port) = host_port
            .rsplit_once(':')
            .unwrap_or((host_port, if proto == "https" { "443" } else { "80" }));
        let port: u16 = port
            .parse()
            .with_context(|| format!("bad port: {}", port))?;
        info!("HTTP GET: {}:{} {}", host, port, method);

        let target = Socks5Addr::Domain(host.to_string(), port);
        let (remote, frame) =
            connect_to_server(server_addr, password, &target, &buf[..pos]).await?;
        relay(local, remote, frame).await
    }
}

async fn socks5_handshake(stream: &mut TcpStream) -> Result<()> {
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    if buf[0] != 0x05 {
        anyhow::bail!("not SOCKS5");
    }
    let nmethods = buf[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;
    stream.write_all(&[0x05, 0x00]).await?;
    Ok(())
}

async fn socks5_read_request(stream: &mut TcpStream) -> Result<Socks5Addr> {
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await?;
    if buf[0] != 0x05 || buf[1] != 0x01 || buf[2] != 0x00 {
        anyhow::bail!("unsupported SOCKS5 request");
    }

    let addr = match buf[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            Socks5Addr::IPv4(ip, u16::from_be_bytes(port))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            let domain_str = String::from_utf8_lossy(&domain).to_string();
            Socks5Addr::Domain(domain_str, u16::from_be_bytes(port))
        }
        0x04 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            Socks5Addr::IPv6(ip, u16::from_be_bytes(port))
        }
        _ => anyhow::bail!("unsupported address type"),
    };

    Ok(addr)
}

async fn socks5_respond_success(stream: &mut TcpStream) -> Result<()> {
    stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        .await?;
    Ok(())
}

async fn relay_local_to_remote(
    reader: &mut (impl AsyncReadExt + Unpin),
    writer: &mut (impl AsyncWriteExt + Unpin),
    frame: &Frame,
) -> Result<()> {
    let mut buf = vec![0u8; MAX_PAYLOAD_LEN];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        let encoded = frame
            .encode(&buf[..n])
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        writer.write_all(&encoded).await?;
    }
    writer.shutdown().await?;
    Ok(())
}

async fn relay_remote_to_local(
    reader: &mut (impl AsyncReadExt + Unpin),
    writer: &mut (impl AsyncWriteExt + Unpin),
    frame: &Frame,
) -> Result<()> {
    let mut buf = vec![0u8; 65536];
    let mut leftover = Vec::new();
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        leftover.extend_from_slice(&buf[..n]);
        loop {
            if leftover.len() < 14 {
                break;
            }
            let ct_len = u16::from_be_bytes([leftover[12], leftover[13]]) as usize;
            let frame_end = 14 + ct_len;
            if leftover.len() < frame_end {
                break;
            }
            let frame_bytes = &leftover[..frame_end];
            let (plain, _) = frame
                .decode(frame_bytes)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            writer.write_all(&plain).await?;
            leftover.drain(..frame_end);
        }
    }
    writer.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ss_core::unpack_addr_payload;

    #[tokio::test]
    async fn plain_http_request_is_sent_as_first_data() {
        let tunnel_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tunnel_addr = tunnel_listener.local_addr().unwrap().to_string();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        let handler = tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            handle_http_connect(stream, &tunnel_addr, "test-password").await
        });
        let tunnel = tokio::spawn(async move {
            let (mut stream, _) = tunnel_listener.accept().await.unwrap();
            let mut salt = vec![0u8; Frame::salt_len()];
            stream.read_exact(&mut salt).await.unwrap();
            let frame = Frame::new("test-password", &salt);
            let mut header = [0u8; 14];
            stream.read_exact(&mut header).await.unwrap();
            let len = u16::from_be_bytes([header[12], header[13]]) as usize;
            let mut encoded = header.to_vec();
            encoded.resize(14 + len, 0);
            stream.read_exact(&mut encoded[14..]).await.unwrap();
            frame.decode(&encoded).unwrap().0
        });

        let request = b"GET http://example.com/test HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut user = TcpStream::connect(proxy_addr).await.unwrap();
        user.write_all(request).await.unwrap();
        user.shutdown().await.unwrap();

        let payload = tunnel.await.unwrap();
        let (address, first_data) = unpack_addr_payload(&payload).unwrap();
        assert!(matches!(address, Socks5Addr::Domain(host, 80) if host == "example.com"));
        assert_eq!(first_data, request);
        handler.await.unwrap().unwrap();
    }
}

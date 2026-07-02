use anyhow::{Context, Result};
use clap::Parser;
use ss_core::{unpack_addr_payload, Frame, Socks5Addr, MAX_PAYLOAD_LEN, TUN_MODE};
#[cfg(target_os = "linux")]
use ss_core::{validate_tun_packet, validate_tun_response, TUN_MTU};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(name = "ss-server")]
struct Args {
    #[arg(short, long, default_value = "0.0.0.0:8388")]
    bind: String,

    #[arg(short, long)]
    password: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let listener = TcpListener::bind(&args.bind)
        .await
        .with_context(|| format!("failed to bind {}", args.bind))?;
    info!("server listening on {}", args.bind);

    let password = Arc::new(args.password);
    let tun_lock = Arc::new(Mutex::new(()));

    loop {
        let (stream, addr) = listener.accept().await?;
        let password = password.clone();
        let tun_lock = tun_lock.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, &password, tun_lock).await {
                error!("connection {} error: {}", addr, e);
            }
        });
    }
}

async fn handle_connection(
    mut client: TcpStream,
    password: &str,
    tun_lock: Arc<Mutex<()>>,
) -> Result<()> {
    let mut salt = vec![0u8; Frame::salt_len()];
    client.read_exact(&mut salt).await?;

    let frame = Frame::new(password, &salt);

    let (plain, _) = read_frame(&mut client, &frame).await?;
    if plain == [TUN_MODE] {
        return handle_tun(client, frame, tun_lock).await;
    }
    let (target, payload) =
        unpack_addr_payload(&plain).map_err(|e| anyhow::anyhow!("bad first payload: {}", e))?;

    info!("proxy request: {:?}", target);

    let target_addr_str = match &target {
        Socks5Addr::IPv4(ip, port) => format!("{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], port),
        Socks5Addr::Domain(domain, port) => format!("{}:{}", domain, port),
        Socks5Addr::IPv6(ip, port) => {
            let s = ip
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(":");
            format!("[{}]:{}", s, port)
        }
    };

    let mut remote = TcpStream::connect(&target_addr_str)
        .await
        .with_context(|| format!("failed to connect to {}", target_addr_str))?;

    if !payload.is_empty() {
        remote.write_all(payload).await?;
    }

    let (mut cr, mut cw) = client.into_split();
    let (mut rr, mut rw) = remote.into_split();

    let frame = Arc::new(frame);

    let f1 = frame.clone();
    let upload = tokio::spawn(async move { relay_download(&mut cr, &mut rw, &f1).await });

    let f2 = frame.clone();
    let download = tokio::spawn(async move { relay_upload(&mut rr, &mut cw, &f2).await });

    let (r1, r2) = tokio::join!(upload, download);
    r1??;
    r2??;
    Ok(())
}

async fn handle_tun(client: TcpStream, frame: Frame, tun_lock: Arc<Mutex<()>>) -> Result<()> {
    let _guard = tun_lock
        .try_lock_owned()
        .map_err(|_| anyhow::anyhow!("another TUN client is already connected"))?;

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (client, frame);
        anyhow::bail!("server TUN mode is supported on Linux only");
    }

    #[cfg(target_os = "linux")]
    {
        let mut config = tun::Configuration::default();
        config
            .tun_name("ss-tun0")
            .address((10, 8, 0, 1))
            .netmask((255, 255, 255, 252))
            .mtu(TUN_MTU as u16)
            .up();
        let device = tun::create_as_async(&config)
            .context("failed to create ss-tun0; CAP_NET_ADMIN is required")?;
        let (mut tun_writer, mut tun_reader) = device.split()?;
        let (mut client_reader, mut client_writer) = client.into_split();

        info!("TUN client connected");
        let inbound = async {
            loop {
                let (packet, _) = read_frame(&mut client_reader, &frame).await?;
                validate_tun_packet(&packet).map_err(anyhow::Error::msg)?;
                tun_writer.write_all(&packet).await?;
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        };
        let outbound = async {
            let mut packet = vec![0u8; TUN_MTU];
            loop {
                let n = tun_reader.read(&mut packet).await?;
                if n == 0 {
                    anyhow::bail!("ss-tun0 closed");
                }
                validate_tun_response(&packet[..n]).map_err(anyhow::Error::msg)?;
                let encoded = frame.encode(&packet[..n]).map_err(anyhow::Error::msg)?;
                client_writer.write_all(&encoded).await?;
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        };

        tokio::select! {
            result = inbound => result,
            result = outbound => result,
        }
    }
}

async fn read_frame(
    reader: &mut (impl AsyncReadExt + Unpin),
    frame: &Frame,
) -> Result<(Vec<u8>, usize)> {
    let mut header = [0u8; 14];
    reader.read_exact(&mut header).await?;
    let ct_len = u16::from_be_bytes([header[12], header[13]]) as usize;
    let mut ciphertext = vec![0u8; ct_len];
    reader.read_exact(&mut ciphertext).await?;
    let mut full_frame = Vec::with_capacity(14 + ct_len);
    full_frame.extend_from_slice(&header);
    full_frame.extend_from_slice(&ciphertext);
    frame
        .decode(&full_frame)
        .map_err(|e| anyhow::anyhow!("{}", e))
}

async fn relay_upload(
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
        let payload = &buf[..n];
        let encoded = frame
            .encode(payload)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        writer.write_all(&encoded).await?;
    }
    writer.shutdown().await?;
    Ok(())
}

async fn relay_download(
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

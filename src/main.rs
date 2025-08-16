mod filters;

use hyper::{Body, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use hyper::body::to_bytes;
use hyper::server::conn::AddrStream;
use std::net::SocketAddr;
use chrono::{Utc, DateTime};
use serde::Serialize;
use std::fs::{OpenOptions};
use std::io::Write;

#[derive(Serialize)]
struct LogEntry {
    timestamp: DateTime<Utc>,
    source_ip: SocketAddr,
    destination_ip: SocketAddr,
    method: String,
    uri: String,
    body: String,
    malicious: bool,
}

fn write_log(entry: &LogEntry) {
    // Консоль
    println!(
        "\nНовый запрос\n {}\n Source: {}\n Destination: {}\n Метод: {}\n URI: {}\n Тело: {}\n Вредоносный: {}\n",
        entry.timestamp,
        entry.source_ip,
        entry.destination_ip,
        entry.method,
        entry.uri,
        entry.body,
        entry.malicious
    );

    // Файл
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("firewall.log")
    {
        if let Ok(json) = serde_json::to_string(entry) {
            let _ = writeln!(file, "{}", json);
        }
    }
}

async fn handle_request(
    req: Request<Body>,
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
) -> Result<Response<Body>, hyper::Error> {
    let method = req.method().to_string();
    let uri = req.uri().to_string();
    let timestamp = Utc::now();

    let body_bytes = to_bytes(req.into_body()).await?;
    let body_str = String::from_utf8_lossy(&body_bytes).into_owned();

    let is_malicious = filters::is_malicious(&body_str);

    let log_entry = LogEntry {
        timestamp,
        source_ip: remote_addr,
        destination_ip: local_addr,
        method,
        uri,
        body: body_str.clone(),
        malicious: is_malicious,
    };

    write_log(&log_entry);

    if is_malicious {
        return Ok(Response::builder()
            .status(403)
            .body(Body::from("Blocked by firewall"))
            .unwrap());
    }

    Ok(Response::new(Body::from("Request accepted")))
}

#[tokio::main]
async fn main() {
    let addr: SocketAddr = ([127, 0, 0, 1], 3000).into();

    let make_svc = make_service_fn(move |conn: &AddrStream| {
        let remote_addr = conn.remote_addr();
        let local_addr = addr;

        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                handle_request(req, remote_addr, local_addr)
            }))
        }
    });

    println!("🚀 Сервер запущен на http://{}", addr);

    if let Err(e) = Server::bind(&addr).serve(make_svc).await {
        eprintln!("Ошибка сервера: {}", e);
    }
}

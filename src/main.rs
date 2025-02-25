use axum::{
    body::Body,
    extract::Request,
    http::{Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};

use hyper::server::conn::http1;
use hyper::upgrade::Upgraded;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tokio::fs::{self, File};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use hyper::service::service_fn;
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Cache directory for storing model files
const CACHE_DIR: &str = "./.cache/demodel";

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!("{}=trace,tower_http=debug", env!("CARGO_CRATE_NAME")).into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Create cache directory if it doesn't exist
    if let Err(e) = fs::create_dir_all(CACHE_DIR).await {
        tracing::error!("Failed to create cache directory: {}", e);
        return;
    }

    let tower_service = service_fn(move |req: Request<_>| {
        let req = req.map(Body::new);
        async move {
            if req.method() == Method::CONNECT {
                proxy(req).await
            } else {
                // Check if we can serve from cache, otherwise forward the request
                handle_http_request(req).await
            }
        }
    });

    let addr = SocketAddr::from(([127, 0, 0, 1], 3128));
    tracing::debug!("listening on {}", addr);

    let listener = TcpListener::bind(addr).await.unwrap();
    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let io = TokioIo::new(stream);
        let tower_service = tower_service.clone();
        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(io, tower_service)
                .with_upgrades()
                .await
            {
                println!("Failed to serve connection: {:?}", err);
            }
        });
    }
}

async fn handle_http_request(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    let uri = req.uri().clone();
    let method = req.method().clone();

    // Only cache GET requests
    if method == Method::GET {
        if let Some(cached_response) = check_cache(&uri).await {
            tracing::info!("Serving cached response for: {}", uri);
            return Ok(cached_response);
        }
    }

    // Forward the request and potentially cache the response
    forward_and_cache(req, uri).await
}

// Check if we have a cached response for this URI
async fn check_cache(uri: &Uri) -> Option<Response> {
    let cache_path = uri_to_cache_path(uri);

    if Path::new(&cache_path).exists() {
        match fs::read(&cache_path).await {
            Ok(data) => {
                let body = Body::from(data);
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .header("X-Cache", "HIT")
                    .body(body)
                    .ok()?;

                Some(response)
            },
            Err(e) => {
                tracing::error!("Failed to read cache file: {}", e);
                None
            }
        }
    } else {
        None
    }
}

// Forward the request to the actual server and cache the response
async fn forward_and_cache(req: Request, uri: Uri) -> Result<Response, hyper::Error> {
    let host = uri.host().expect("uri has no host");
    let port = uri.port_u16().unwrap_or(80);
    let addr = format!("{}:{}", host, port);
    let stream = TcpStream::connect(addr).await.unwrap();
    let io = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {:?}", err);
        }
    });

    let response = sender.send_request(req).await?;

    // Check if this is a successful response that we should cache
    if response.status().is_success() {
        // Convert the response to bytes
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await?.to_bytes();

        // Create a new response with the same body
        let new_response = Response::from_parts(parts, Body::from(bytes.clone()));

        // Cache the response in the background
        let cache_path = uri_to_cache_path(&uri);
        tokio::spawn(async move {
            if let Err(e) = cache_response(&cache_path, &bytes).await {
                tracing::error!("Failed to cache response: {}", e);
            }
        });

        Ok(new_response)
    } else {
        // Just return the response without caching for non-200 responses
        Ok(response.map(Body::new))
    }
}

// Convert a URI to a cache file path
fn uri_to_cache_path(uri: &Uri) -> PathBuf {
    let mut path = PathBuf::from(CACHE_DIR);

    // Use the host and path to create a unique cache file
    if let Some(authority) = uri.authority() {
        path.push(authority.host());
    }

    // Create a file name from the path and query
    let mut file_name = uri.path().replace("/", "_");
    if let Some(query) = uri.query() {
        file_name.push_str("_");
        file_name.push_str(&query.replace("&", "_"));
    }

    // If the file name is empty (e.g., for "/"), use "index"
    if file_name.is_empty() || file_name == "_" {
        file_name = "index".to_string();
    }

    path.push(file_name);
    path
}

// Cache the response body to a file
async fn cache_response(path: &Path, data: &[u8]) -> std::io::Result<()> {
    // Create parent directories if they don't exist
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }

    // Write the data to the cache file
    let mut file = File::create(path).await?;
    file.write_all(data).await?;

    tracing::info!("Cached response to: {}", path.display());
    Ok(())
}

async fn proxy(req: Request) -> Result<Response, hyper::Error> {
    tracing::trace!(?req);

    if let Some(host_addr) = req.uri().authority().map(|auth| auth.to_string()) {
        tokio::task::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    if let Err(e) = tunnel(upgraded, host_addr).await {
                        tracing::warn!("server io error: {}", e);
                    };
                }
                Err(e) => tracing::warn!("upgrade error: {}", e),
            }
        });

        Ok(Response::new(Body::empty()))
    } else {
        tracing::warn!("CONNECT host is not socket addr: {:?}", req.uri());
        Ok((
            StatusCode::BAD_REQUEST,
            "CONNECT must be to a socket address",
        )
            .into_response())
    }
}

async fn tunnel(upgraded: Upgraded, addr: String) -> std::io::Result<()> {
    let mut server = TcpStream::connect(addr).await?;
    let mut upgraded = TokioIo::new(upgraded);

    let (from_client, from_server) =
        tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;

    tracing::debug!(
        "client wrote {} bytes and received {} bytes",
        from_client,
        from_server
    );

    Ok(())
}

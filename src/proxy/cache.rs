use bytes::Bytes;
use futures::stream::Stream;
use http_body_util::{BodyExt, Full};
use hudsucker::{
    hyper::{Request, Response, StatusCode, Uri},
    Body, HttpContext, HttpHandler, RequestOrResponse,
};
use hyper::HeaderMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::{
    fs::create_dir_all,
    hash::{DefaultHasher, Hash, Hasher},
};
use tokio::io::AsyncWriteExt;
use tracing::{error, info};
use uuid::Uuid;

use super::config::ProxyConfig;
use super::handler::LogHandler;

#[derive(Clone)]
pub struct CacheHandler {
    cache_dir: PathBuf,
    inner: LogHandler,
    proxy_config: ProxyConfig,
    request_map: Arc<Mutex<HashMap<Uuid, RequestInfo>>>,
    file_writer: Option<tokio::sync::mpsc::Sender<(Vec<u8>, PathBuf)>>,
}

#[derive(Serialize, Deserialize)]
struct CachedResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

// Define a stream that tees data to both the original destination and a file
struct TeeStream<S> {
    inner: S,
    cache_path: Option<PathBuf>,
    sender: Option<tokio::sync::mpsc::Sender<(Vec<u8>, PathBuf)>>,
}

impl<S, E> Stream for TeeStream<S>
where
    S: Stream<Item = Result<hyper::body::Bytes, E>> + Unpin,
    E: std::error::Error,
{
    type Item = Result<hyper::body::Bytes, E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                if let Some(path) = &self.cache_path {
                    // Clone the chunk and path for sending
                    let chunk_vec = chunk.to_vec();
                    let path_clone = path.clone();

                    // Send to the writer task
                    if let Some(sender) = &self.sender {
                        let sender = sender.clone();
                        tokio::spawn(async move {
                            if let Err(e) = sender.send((chunk_vec, path_clone)).await {
                                error!("Failed to send chunk to writer: {:?}", e);
                            }
                        });
                    }
                }
                Poll::Ready(Some(Ok(chunk)))
            }
            other => other,
        }
    }
}

impl CacheHandler {
    pub fn new<P: AsRef<Path>>(cache_dir: P) -> Self {
        let cache_dir = cache_dir.as_ref().to_path_buf();
        // Create cache directory if it doesn't exist
        if !cache_dir.exists() {
            create_dir_all(&cache_dir).expect("Failed to create cache directory");
        }

        // Create a channel for file writing
        let (tx, mut rx) = tokio::sync::mpsc::channel::<(Vec<u8>, PathBuf)>(100);

        // Spawn a dedicated task for file writing
        tokio::spawn(async move {
            while let Some((data, path)) = rx.recv().await {
                if let Ok(mut file) = tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .await
                {
                    if let Err(e) = file.write_all(&data).await {
                        error!("Failed to write to cache file: {:?}", e);
                    }
                }
            }
        });

        Self {
            cache_dir,
            inner: LogHandler,
            proxy_config: ProxyConfig::new(),
            request_map: Arc::new(Mutex::new(HashMap::new())),
            file_writer: Some(tx),
        }
    }

    fn cache_path(&self, uri: &Uri) -> PathBuf {
        // Extract the host from the URI
        let host = uri.host().unwrap_or("unknown_host").to_string();

        // Create a hash of the URI to use as the filename
        let mut hasher = Sha256::new();
        hasher.update(uri.to_string().as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        // Create host directory and subdirectories based on the first few characters of the hash
        let host_dir = self.cache_dir.join(host);
        let subdir = &hash[0..2];
        let path = host_dir.join(subdir);

        if !path.exists() {
            create_dir_all(&path).expect("Failed to create cache subdirectory");
        }

        path.join(hash)
    }

    async fn is_cached(&self, uri: &Uri) -> bool {
        let path = self.cache_path(uri);
        path.exists()
    }

    async fn get_from_cache(&self, uri: &Uri) -> Option<Response<Body>> {
        let path = self.cache_path(uri);

        match tokio::fs::read(path).await {
            Ok(data) => {
                match bincode::deserialize::<CachedResponse>(&data) {
                    Ok(cached) => {
                        let mut response = Response::builder().status(cached.status);

                        // Add headers
                        for (name, value) in &cached.headers {
                            response = response.header(name, value);
                        }

                        // Create response with body and convert to the expected type
                        match response.body(Full::new(Bytes::from(cached.body))) {
                            Ok(full_response) => {
                                // Convert from Response<Full<Bytes>> to Response<Body>
                                let (parts, full_body) = full_response.into_parts();
                                let body = Body::from(full_body);
                                let res = Response::from_parts(parts, body);

                                info!("Cache hit for {}", uri);
                                Some(res)
                            }
                            Err(_) => None,
                        }
                    }
                    Err(e) => {
                        info!("Failed to deserialize cached response: {}", e);
                        None
                    }
                }
            }
            Err(_) => None,
        }
    }

    // This function is currently not being used in the codebase.
    // It attempts to save a response to cache, but only stores headers without the body,
    // which makes it incomplete for proper caching functionality.
    //
    // If we want to implement proper caching, we would need to:
    // 1. Capture the full response body
    // 2. Store it along with headers and status
    // 3. Call this function from handle_response
    //
    // For now, keeping it as a placeholder for future implementation.
    async fn _save_to_cache(
        &self,
        uri: &Uri,
        res: &Response<Body>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = self.cache_path(uri);

        // Clone the response parts
        let status = res.status().as_u16();

        // Convert headers to a serializable format
        let headers: Vec<(String, String)> = res
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                if let Ok(value_str) = value.to_str() {
                    Some((name.to_string(), value_str.to_string()))
                } else {
                    None
                }
            })
            .collect();

        // We need to get the body bytes, but we can't consume the body
        // This is a limitation - we can only cache responses we can read without consuming
        // For now, we'll create an empty body placeholder
        let body_bytes: Vec<u8> = Vec::new();

        // Create our serializable structure
        let cached = CachedResponse {
            status,
            headers,
            body: body_bytes,
        };

        // Serialize the response
        let serialized = bincode::serialize(&cached)?;

        // Write to file
        tokio::fs::write(path, serialized).await?;
        info!("Cached response for {} (headers only)", uri);

        Ok(())
    }
}

impl HttpHandler for CacheHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        let method = req.method().clone();
        let uri = req.uri().clone();

        // Generate a unique ID for this request
        let request_id = Uuid::new_v4();

        // Store the original URI and method with the request ID
        {
            let mut map = self.request_map.lock().unwrap();
            map.insert(
                request_id,
                RequestInfo {
                    uri: uri.clone(),
                    method: method.clone(),
                },
            );
        }

        // Add the request ID as an extension to the request
        let mut req = req;
        req.extensions_mut().insert(request_id);

        // Check cache first using original URI
        if method == hyper::Method::GET {
            if self.is_cached(&uri).await {
                if let Some(cached_response) = self.get_from_cache(&uri).await {
                    return RequestOrResponse::Response(cached_response);
                }
            }
        }

        // If we need to rewrite the request, we'll need to convert it to parts,
        // modify the URI, and rebuild it
        if let Some(host) = uri.host() {
            if let Some(mirror_url) = self.proxy_config.get_mirror_for_host(host) {
                // Convert request to parts
                let (mut parts, body) = req.into_parts();

                // Try to create a new URI with the mirror
                if let Ok(mirror_uri) = mirror_url.parse::<Uri>() {
                    if let Ok(new_uri) = Uri::builder()
                        .scheme(mirror_uri.scheme_str().unwrap_or("https"))
                        .authority(mirror_uri.authority().unwrap().clone())
                        .path_and_query(uri.path_and_query().unwrap().clone())
                        .build()
                    {
                        // Update URI in parts
                        parts.uri = new_uri;

                        // Add original host header
                        if let Ok(host_value) = hyper::header::HeaderValue::from_str(host) {
                            parts.headers.insert(hyper::header::HOST, host_value);
                        }

                        // Rebuild request
                        let modified_req = Request::from_parts(parts, body);
                        info!(
                            "Rewritten request to mirror: {} -> {}",
                            uri,
                            modified_req.uri()
                        );
                        return RequestOrResponse::Request(modified_req);
                    }
                }

                // If we got here, something went wrong with rewriting
                // Rebuild the original request and continue
                let original_req = Request::from_parts(parts, body);
                return RequestOrResponse::Request(original_req);
            }
        }

        // No rewriting needed, return the original request
        RequestOrResponse::Request(req)
    }

    fn handle_response(
        &mut self,
        ctx: &HttpContext,
        res: Response<Body>,
    ) -> impl Future<Output = Response<Body>> + Send {
        // Extract what we need before moving the response
        let status = res.status();
        let headers = res.headers().clone();
        let mut inner = self.inner.clone();
        let cache_dir = self.cache_dir.clone();
        let request_map = self.request_map.clone();

        // Get the request ID from the response extensions
        let request_id = res.extensions().get::<Uuid>().cloned();

        // Get the request info using the request ID
        let (uri, method) = if let Some(id) = request_id {
            let mut map = request_map.lock().unwrap();
            if let Some(info) = map.remove(&id) {
                (Some(info.uri), Some(info.method))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        let uri = uri.unwrap_or_else(|| {
            Uri::builder()
                .scheme("http")
                .authority(ctx.client_addr.to_string())
                .path_and_query("/")
                .build()
                .unwrap_or_default()
        });

        let method = method.unwrap_or(hyper::Method::GET);

        async move {
            // Only try to cache successful GET responses
            let should_cache = status.is_success() && method == hyper::Method::GET;

            if should_cache {
                // Create cache file path
                let cache_path = create_cache_path(&cache_dir, &uri);

                // Create parent directories if they don't exist
                if let Some(parent) = cache_path.parent() {
                    if let Err(e) = tokio::fs::create_dir_all(parent).await {
                        error!("Failed to create cache directory: {:?}", e);
                        return inner.handle_response(ctx, res).await;
                    }
                }

                // Open file for writing
                match tokio::fs::File::create(&cache_path).await {
                    Ok(_file) => {
                        // Write headers to a separate metadata file
                        let meta_path = cache_path.with_extension("meta");
                        if let Err(e) = save_response_metadata(&meta_path, &status, &headers).await
                        {
                            error!("Failed to save response metadata: {:?}", e);
                        }

                        // Create a new response with a tee'd body
                        let (parts, body) = res.into_parts();
                        let tee_stream = TeeStream {
                            inner: body.into_data_stream(),
                            cache_path: Some(cache_path),
                            sender: self.file_writer.clone(),
                        };

                        let tee_body = Body::from_stream(tee_stream);
                        let new_response = Response::from_parts(parts, tee_body);

                        info!("Caching full response for {}", uri);
                        inner.handle_response(ctx, new_response).await
                    }
                    Err(e) => {
                        error!("Failed to create cache file: {:?}", e);
                        inner.handle_response(ctx, res).await
                    }
                }
            } else {
                // Not caching this response
                inner.handle_response(ctx, res).await
            }
        }
    }

    fn handle_error(
        &mut self,
        _: &HttpContext,
        err: hyper_util::client::legacy::Error,
    ) -> impl Future<Output = Response<Body>> + Send {
        async move {
            error!("Failed to forward request: {}", err);
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::empty())
                .expect("Failed to build response")
        }
    }

    fn should_intercept(
        &mut self,
        _ctx: &HttpContext,
        _req: &Request<Body>,
    ) -> impl Future<Output = bool> + Send {
        async { true }
    }
}

// Helper function to create a cache path from a URI
fn create_cache_path(cache_dir: &Path, uri: &Uri) -> PathBuf {
    let mut hasher = DefaultHasher::new();
    uri.to_string().hash(&mut hasher);
    let hash = hasher.finish();

    let mut path = PathBuf::from(cache_dir);
    path.push(format!("{:016x}", hash));
    path
}

// Helper function to save response metadata
async fn save_response_metadata(
    path: &Path,
    status: &StatusCode,
    headers: &HeaderMap,
) -> Result<(), std::io::Error> {
    let mut file = tokio::fs::File::create(path).await?;

    // Write status code
    file.write_all(format!("{}\n", status.as_u16()).as_bytes())
        .await?;

    // Write headers
    for (name, value) in headers.iter() {
        if let Ok(value_str) = value.to_str() {
            file.write_all(format!("{}:{}\n", name, value_str).as_bytes())
                .await?;
        }
    }

    Ok(())
}

// Add a RequestInfo struct to store both URI and method
struct RequestInfo {
    uri: Uri,
    method: hyper::Method,
}

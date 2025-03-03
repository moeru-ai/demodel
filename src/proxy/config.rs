use std::collections::HashMap;
use std::env;

#[derive(Clone)]
pub struct ProxyConfig {
    pub mirrors: HashMap<String, String>,
}

impl ProxyConfig {
    pub fn new() -> Self {
        let mut mirrors = HashMap::new();

        // Handle HuggingFace mirrors
        if let Ok(mirror_url) = env::var("HF_MIRROR_URL") {
            mirrors.insert("huggingface.co".to_string(), mirror_url);
        } else if env::var("USE_HF_MIRROR").is_ok() {
            mirrors.insert(
                "huggingface.co".to_string(),
                "https://hf-mirror.com".to_string(),
            );
        }

        // Handle Ollama registry mirrors
        if let Ok(ollama_mirror) = env::var("OLLAMA_MIRROR_URL") {
            mirrors.insert("registry.ollama.ai".to_string(), ollama_mirror);
        }

        // Add more mirrors as needed
        // You can also implement a more generic approach using environment variables
        // like MIRROR_example.com=https://mirror.example.com

        Self { mirrors }
    }

    pub fn get_mirror_for_host(&self, host: &str) -> Option<String> {
        self.mirrors.get(host).cloned()
    }
}

use directories::ProjectDirs;
use std::env;
use std::path::PathBuf;

// Function to get the config directory path
pub fn get_config_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    // Try to get XDG_CONFIG_HOME first (Linux/macOS)
    if let Ok(config_home) = env::var("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(config_home).join("demodel"));
    }

    // Fall back to platform-specific directories
    if let Some(proj_dirs) = ProjectDirs::from("com.github", "moeru-ai", "demodel") {
        return Ok(proj_dirs.config_dir().to_path_buf());
    }

    Err("Could not determine config directory".into())
}

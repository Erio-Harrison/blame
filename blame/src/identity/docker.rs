//! Container names from the Docker engine socket.

use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
    os::unix::net::UnixStream,
    time::Duration,
};

use anyhow::{Context as _, Result, bail};

const SOCKET: &str = "/var/run/docker.sock";

/// Container id (64 hex) -> name. Empty when Docker is not installed.
pub fn container_names() -> Result<HashMap<String, String>> {
    if !std::path::Path::new(SOCKET).exists() {
        return Ok(HashMap::new());
    }
    let body = get("/containers/json?all=1").context("querying the Docker socket")?;
    parse_names(&body)
}

/// Plain HTTP/1.0 request over the Unix socket, so the reply is never chunked.
fn get(path: &str) -> Result<String> {
    let mut stream = UnixStream::connect(SOCKET)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    write!(stream, "GET {path} HTTP/1.0\r\nHost: docker\r\n\r\n")?;
    let mut reply = String::new();
    stream.read_to_string(&mut reply)?;
    let (head, body) = reply
        .split_once("\r\n\r\n")
        .context("malformed HTTP reply")?;
    if !head.starts_with("HTTP/1.0 200") && !head.starts_with("HTTP/1.1 200") {
        bail!("Docker replied: {}", head.lines().next().unwrap_or(""));
    }
    Ok(body.to_string())
}

fn parse_names(json: &str) -> Result<HashMap<String, String>> {
    let value: serde_json::Value = serde_json::from_str(json).context("parsing container list")?;
    let list = value.as_array().context("container list is not an array")?;
    let mut out = HashMap::new();
    for item in list {
        let id = item.get("Id").and_then(|v| v.as_str());
        // Docker reports names with a leading slash.
        let name = item
            .get("Names")
            .and_then(|v| v.get(0))
            .and_then(|v| v.as_str())
            .map(|n| n.trim_start_matches('/'));
        if let (Some(id), Some(name)) = (id, name) {
            out.insert(id.to_string(), name.to_string());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_lose_their_leading_slash() {
        let json = r#"[{"Id":"abc","Names":["/nw-test"]},{"Id":"def","Names":[]}]"#;
        let names = parse_names(json).unwrap();
        assert_eq!(names.get("abc").map(String::as_str), Some("nw-test"));
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn non_array_is_an_error() {
        assert!(parse_names("{}").is_err());
    }
}

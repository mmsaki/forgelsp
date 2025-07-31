use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut child = Command::new("cargo")
        .arg("run")
        .arg("--bin")
        .arg("lsp")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;

    let mut server_stdin = child.stdin.take().unwrap();
    let mut server_stdout = child.stdout.take().unwrap();

    let initialize_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "processId": null,
            "rootUri": null,
            "capabilities": {}
        }
    });
    let body = initialize_request.to_string();
    let header = format!("Content-Length: {}\r\n\r\n", body.len());

    server_stdin.write_all(header.as_bytes()).await?;
    server_stdin.write_all(body.as_bytes()).await?;
    server_stdin.flush().await?;

    let mut buf = [0; 2048];
    let n = server_stdout.read(&mut buf).await?;
    let response = String::from_utf8_lossy(&buf[..n]);
    println!("Client received: \n{}", response);

    Ok(())
}

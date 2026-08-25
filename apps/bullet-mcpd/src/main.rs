use bullet_mcpd::transport::BoundedLines;
use bullet_mcpd::{BulletMcp, LoopbackFarmd};
use rmcp::ServiceExt;

const DEFAULT_FARMD_URL: &str = "http://127.0.0.1:7420";

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("bullet-mcpd: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let base = parse_args(std::env::args().skip(1))?;
    let farmd = LoopbackFarmd::new(&base).map_err(|error| error.to_string())?;
    let transport = rmcp::transport::async_rw::AsyncRwTransport::new_server(
        BoundedLines::mcp(tokio::io::stdin()),
        tokio::io::stdout(),
    );
    let service = BulletMcp::new(farmd)
        .serve(transport)
        .await
        .map_err(|error| format!("MCP initialization: {error}"))?;
    service
        .waiting()
        .await
        .map_err(|error| format!("MCP service: {error}"))?;
    Ok(())
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<String, String> {
    let mut args = args.into_iter();
    let Some(first) = args.next() else {
        return Ok(DEFAULT_FARMD_URL.into());
    };
    if first != "--farmd-url" {
        return Err("usage: bullet-mcpd [--farmd-url http://<numeric-loopback>:<port>]".into());
    }
    let value = args
        .next()
        .ok_or_else(|| "--farmd-url requires a value".to_owned())?;
    if args.next().is_some() {
        return Err("usage: bullet-mcpd [--farmd-url http://<numeric-loopback>:<port>]".into());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_are_exact() {
        assert_eq!(parse_args(std::iter::empty()).unwrap(), DEFAULT_FARMD_URL);
        assert_eq!(
            parse_args(["--farmd-url".into(), "http://127.0.0.1:1".into()]).unwrap(),
            "http://127.0.0.1:1"
        );
        assert!(parse_args(["--other".into()]).is_err());
        assert!(parse_args(["--farmd-url".into()]).is_err());
        assert!(parse_args(["--farmd-url".into(), "x".into(), "y".into()]).is_err());
    }
}

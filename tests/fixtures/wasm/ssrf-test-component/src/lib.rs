wit_bindgen::generate!();

use std::io::{Read, Write};
use std::net::TcpStream;

struct Component;

impl exports::makiatto::http::handler::Guest for Component {
    fn handle_request(
        _ctx: exports::makiatto::http::handler::NodeContext,
        req: exports::makiatto::http::handler::Request,
    ) -> exports::makiatto::http::handler::Response {
        // Extract target IP from query parameter
        let target = req
            .query
            .as_ref()
            .and_then(|q| q.strip_prefix("target="))
            .unwrap_or("8.8.8.8:80");

        // Try to connect to the target
        let result = match TcpStream::connect(target) {
            Ok(mut stream) => {
                // Try to send a simple HTTP request
                let _ = stream.write_all(b"GET / HTTP/1.0\r\n\r\n");
                let mut buf = [0u8; 128];
                let _ = stream.read(&mut buf);
                format!("SUCCESS: Connected to {}", target)
            }
            Err(e) => format!("BLOCKED: {}", e),
        };

        exports::makiatto::http::handler::Response {
            status: 200,
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            body: Some(result.into_bytes()),
        }
    }
}

export!(Component);

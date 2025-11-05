wit_bindgen::generate!({
    world: "http-handler",
});

use exports::makiatto::http::handler::Guest;

struct Component;

impl Guest for Component {
    fn handle_request(req: exports::makiatto::http::handler::Request) -> exports::makiatto::http::handler::Response {
        // Simple handler that echoes request info
        let body = format!(
            "Method: {:?}\nPath: {}\nQuery: {:?}\nHeaders: {:?}",
            req.method, req.path, req.query, req.headers
        );

        exports::makiatto::http::handler::Response {
            status: 200,
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            body: Some(body.into_bytes()),
        }
    }
}

export!(Component);

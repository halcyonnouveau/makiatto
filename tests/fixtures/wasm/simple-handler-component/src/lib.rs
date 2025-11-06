wit_bindgen::generate!();

struct Component;

impl exports::makiatto::http::handler::Guest for Component {
    fn handle_request(
        ctx: exports::makiatto::http::handler::NodeContext,
        req: exports::makiatto::http::handler::Request,
    ) -> exports::makiatto::http::handler::Response {
        let body = format!(
            "Node: {} @ ({}, {})\nMethod: {:?}\nPath: {}\nQuery: {:?}\nHeaders: {:?}",
            ctx.name, ctx.latitude, ctx.longitude, req.method, req.path, req.query, req.headers
        );

        exports::makiatto::http::handler::Response {
            status: 200,
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            body: Some(body.into_bytes()),
        }
    }
}

export!(Component);

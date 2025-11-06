wit_bindgen::generate!();

struct Component;

impl exports::makiatto::transform::transformer::Guest for Component {
    fn transform(
        ctx: exports::makiatto::transform::transformer::NodeContext,
        info: exports::makiatto::transform::transformer::FileInfo,
        content: Vec<u8>,
    ) -> Option<exports::makiatto::transform::transformer::TransformResult> {
        let transformed = if info.mime_type.contains("html") {
            let html_content = String::from_utf8_lossy(&content);
            let new_content = format!(
                "<!-- Transformed by WASM on node {} @ ({}, {}): {} -->\n{}",
                ctx.name, ctx.latitude, ctx.longitude, info.path, html_content
            );
            new_content.into_bytes()
        } else if info.mime_type.contains("text") || info.mime_type.contains("javascript") {
            let text_content = String::from_utf8_lossy(&content);
            let new_content = format!(
                "// Transformed by node {} @ ({}, {}): {}\n{}",
                ctx.name, ctx.latitude, ctx.longitude, info.path, text_content
            );
            new_content.into_bytes()
        } else {
            let mut new_content = b"TRANSFORMED:".to_vec();
            new_content.extend_from_slice(&content);
            new_content
        };

        Some(exports::makiatto::transform::transformer::TransformResult {
            content: transformed,
            mime_type: Some(info.mime_type),
            headers: vec![("x-transformed".to_string(), "true".to_string())],
        })
    }
}

export!(Component);

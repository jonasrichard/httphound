use std::{collections::HashMap, io::Read, str::FromStr};

use bytes::BytesMut;
use flate2::read::MultiGzDecoder;

pub struct Req {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

pub struct Resp {
    pub version: String,
    pub code: u16,
    pub reason: Option<String>,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

impl std::fmt::Debug for Req {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Req")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("version", &self.version)
            .field("headers", &self.headers)
            .field("body", &self.body)
            .finish()
    }
}

impl std::fmt::Debug for Resp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resp")
            .field("version", &self.version)
            .field("code", &self.code)
            .field("reason", &self.reason)
            .field("headers", &self.headers)
            .field("body", &self.body)
            .finish()
    }
}

/// Parse the request headers and request body as well. Advance the `BytesMut` buffer
/// according to Content-Length header.
pub fn parse_request(req_bytes: &mut BytesMut) -> Result<Req, Box<dyn std::error::Error>> {
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut parsed_req = httparse::Request::new(&mut headers);
    let res = parsed_req.parse(req_bytes)?;

    if res.is_partial() {
        return Err("Partial request".into());
    }

    let mut req = Req {
        method: parsed_req.method.unwrap().to_string(),
        path: parsed_req.path.unwrap().to_string(),
        version: parsed_req.version.unwrap().to_string(),
        headers: HashMap::new(),
        body: None,
    };

    for header in parsed_req.headers {
        req.headers.insert(
            header.name.to_string(),
            String::from_utf8(header.value.to_vec()).unwrap(),
        );
    }

    let body_start = res.unwrap();

    let _ = req_bytes.split_to(body_start);

    if let Some(content_length) = get_content_length(&req.headers) {
        if content_length > 0 {
            let body_buf = req_bytes.split_to(content_length);

            let body =
                String::from_utf8(body_buf.to_vec()).unwrap_or("Body encoding error".to_string());

            req.body = Some(body);
        }
    }

    Ok(req)
}

pub fn parse_response(resp_bytes: &mut BytesMut) -> Result<Resp, Box<dyn std::error::Error>> {
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut parsed_resp = httparse::Response::new(&mut headers);
    let res = parsed_resp.parse(resp_bytes).unwrap();

    if res.is_partial() {
        return Err("Partial response".into());
    }

    let mut resp = Resp {
        version: parsed_resp.version.unwrap().to_string(),
        code: parsed_resp.code.unwrap(),
        reason: parsed_resp.reason.map(|r| r.to_string()),
        headers: HashMap::new(),
        body: None,
    };

    for header in parsed_resp.headers {
        resp.headers.insert(
            header.name.to_string(),
            String::from_utf8(header.value.to_vec())?,
        );
    }

    let body_start = res.unwrap();

    let _ = resp_bytes.split_to(body_start);

    if let Some(content_length) = get_content_length(&resp.headers) {
        let body_buf = resp_bytes.split_to(content_length);

        if let Some(enc) = resp.headers.get("Content-Encoding") {
            if enc == "gzip" {
                resp.body = Some(unzip_content(&body_buf)?);
            } else {
                return Err(format!("Unknown encoding {enc}").into());
            }
        } else {
            resp.body =
                Some(String::from_utf8(body_buf.to_vec()).unwrap_or("Encoding error".to_string()));
        }
    }

    Ok(resp)
}

fn get_content_length(headers: &HashMap<String, String>) -> Option<usize> {
    for (k, v) in headers {
        if "content-length" == k.to_lowercase() {
            return usize::from_str(v).ok();
        }
    }

    None
}

fn unzip_content(buf: &[u8]) -> Result<String, std::io::Error> {
    let mut gz = MultiGzDecoder::new(buf);
    let mut s = String::new();

    gz.read_to_string(&mut s)?;

    Ok(s)
}

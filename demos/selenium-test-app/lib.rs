use candid::{CandidType, Deserialize, Principal};
use ic_cdk::api;
use ic_cdk_macros::{init, post_upgrade, query, update};
use lazy_static::lazy_static;
use serde_bytes::{ByteBuf, Bytes};
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;

thread_local! {
    static ASSETS: RefCell<HashMap<&'static str, (Vec<(String, String)>, Vec<u8>)>> = RefCell::new(HashMap::default());
}

#[derive(Debug, PartialEq, Eq)]
pub enum ContentType {
    HTML,
    JS,
    JSON,
}

impl ContentType {
    pub fn to_mime_type_string(&self) -> String {
        match self {
            ContentType::HTML => "text/html".to_string(),
            ContentType::JS => "text/javascript".to_string(),
            ContentType::JSON => "application/json".to_string(),
        }
    }
}

#[query]
fn whoami() -> Principal {
    api::caller()
}

#[update]
fn update_alternative_origins(content: String) {
    ASSETS.with(|a| {
        let mut assets = a.borrow_mut();
        assets.insert(
            "/.well-known/ii-alternative-origins",
            (
                vec![(
                    "Content-Type".to_string(),
                    ContentType::JSON.to_mime_type_string(),
                )],
                content.as_bytes().to_vec(),
            ),
        )
    });
}

pub type HeaderField = (String, String);

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: ByteBuf,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: Vec<HeaderField>,
    pub body: Cow<'static, Bytes>,
}

#[query]
pub fn http_request(req: HttpRequest) -> HttpResponse {
    let parts: Vec<&str> = req.url.split('?').collect();
    let mut headers = vec![];
    headers.push(("Access-Control-Allow-Origin".to_string(), "*".to_string()));

    ASSETS.with(|a| match a.borrow().get(parts[0]) {
        Some((asset_headers, value)) => {
            headers.append(&mut asset_headers.clone());

            HttpResponse {
                status_code: 200,
                headers,
                body: Cow::Owned(ByteBuf::from(value.clone())),
            }
        }
        None => HttpResponse {
            status_code: 404,
            headers,
            body: Cow::Owned(ByteBuf::from(format!("Asset {} not found.", parts[0]))),
        },
    })
}

#[init]
#[post_upgrade]
pub fn init_assets() {
    ASSETS.with(|a| {
        let mut assets = a.borrow_mut();
        for (path, content, content_type) in get_assets() {
            let mut headers = vec![];
            headers.push((
                "Content-Type".to_string(),
                content_type.to_mime_type_string(),
            ));
            assets.insert(path, (headers, content.to_vec()));
        }
    });
}

lazy_static! {
    // The full content of the index.html, after the canister ID (and script tag) have been
    // injected
    static ref INDEX_HTML_STR: String = {
        let canister_id = api::id();
        let index_html = include_str!("dist/index.html");
        let index_html = index_html.replace(
            r#"<script defer="defer" src="bundle.js"></script>"#,
            &format!(r#"<script id="setupJs">var canisterId = '{canister_id}';</script><script defer="defer" src="bundle.js"></script>"#).to_string()
        );
        index_html
    };
}

// Get all the assets. Duplicated assets like index.html are shared and generally all assets are
// prepared only once (like injecting the canister ID).
fn get_assets() -> [(&'static str, &'static [u8], ContentType); 4] {
    let index_html: &[u8] = INDEX_HTML_STR.as_bytes();
    [
        ("/", index_html, ContentType::HTML),
        ("/index.html", index_html, ContentType::HTML),
        (
            "/bundle.js",
            include_bytes!("dist/bundle.js"),
            ContentType::JS,
        ),
        (
            "/.well-known/ii-alternative-origins",
            b"{\"alternativeOrigins\":[]}",
            ContentType::JSON,
        ),
    ]
}

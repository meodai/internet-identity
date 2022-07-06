use ic_cdk_macros::{query, update};
use std::cell::RefCell;
use std::collections::HashMap;

thread_local! {
    static STATE: String = "".to_string();
    static ASSETS: RefCell<HashMap<&'static str, (Vec<(String, String)>, &'static [u8])>> = RefCell::new(HashMap::default());
}

#[query]
fn greet(name: String) -> String {
    format!("Hello, {}!", name)
}

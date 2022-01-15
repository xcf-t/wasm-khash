mod constants;
mod utils;
mod rar;

use std::io::Cursor;
use wasm_bindgen::prelude::*;
use crate::utils::ProcessingResult;

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern {
    fn alert(s: &str);

    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn console_log(s: &str);
}

#[wasm_bindgen]
pub fn execute_analyzer(data: &[u8]) -> String {
    let cursor = Cursor::new(Vec::from(data));

    let result = rar::process_file(cursor).unwrap();

    return match result {
        ProcessingResult::Rar5(res) => {
            res.found.join("\n")
        },
        _ => {
            String::new()
        }
    }
}

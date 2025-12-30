use rhai::{Engine, Scope, Map, Dynamic};

pub struct ScriptEngine {
    pub engine: Engine,
    pub ast: Option<rhai::AST>, // Compiled script
}

impl Default for ScriptEngine {
    fn default() -> Self {
        Self {
            engine: Engine::new(),
            ast: None,
        }
    }
}

impl ScriptEngine {
    pub fn compile(&mut self, script: &str) -> Result<(), String> {
        match self.engine.compile(script) {
            Ok(ast) => {
                self.ast = Some(ast);
                Ok(())
            },
            Err(e) => Err(e.to_string()),
        }
    }

    // Input: request details. Output: modified request details (optional)
    pub fn on_request(&self, method: &str, url: &str, headers: &str, body: &str) -> Result<Option<(String, String, String, String)>, String> { // (Method, Url, Headers, Body)
        if let Some(ast) = &self.ast {
             let mut scope = Scope::new();
             
             // Create Request Map
             let mut req_map = Map::new();
             req_map.insert("method".into(), method.into());
             req_map.insert("url".into(), url.into());
             req_map.insert("headers".into(), headers.into()); // User parses JSON in rhai or treat as string? String is safer for simple MVP.
             req_map.insert("body".into(), body.into());
             
             // Call function
             let result: Dynamic = self.engine.call_fn(&mut scope, ast, "on_request", (req_map.clone(),)) 
                .or_else(|_| Ok::<Dynamic, Box<rhai::EvalAltResult>>(Dynamic::UNIT)).map_err(|e| e.to_string())?; // If function undefined, ignore errors? No, we should probably check existence.
             
             // If result is a Map, it means modification
             if result.is_map() {
                 let res_map = result.cast::<Map>();
                 let method_out = res_map.get("method").map(|v| v.to_string()).unwrap_or(method.to_string());
                 let url_out = res_map.get("url").map(|v| v.to_string()).unwrap_or(url.to_string());
                 let headers_out = res_map.get("headers").map(|v| v.to_string()).unwrap_or(headers.to_string());
                 let body_out = res_map.get("body").map(|v| v.to_string()).unwrap_or(body.to_string());
                 
                 return Ok(Some((method_out, url_out, headers_out, body_out)));
             }
        }
        Ok(None)
    }
}

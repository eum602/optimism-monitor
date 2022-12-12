use std::env;

pub struct Utils {}

impl Utils {
    pub fn get_env_or_err(env_name: &'static str) -> Result<String, &'static str> {
        match env::var(env_name) {
            Ok(s) => Ok(s),
            Err(_) => Err("not found"),
        }
    }
}

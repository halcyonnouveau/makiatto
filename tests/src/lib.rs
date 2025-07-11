mod container;
mod e2e;

use std::sync::Once;

static INIT: Once = Once::new();

#[ctor::ctor]
fn init_test_env() {
    INIT.call_once(|| unsafe {
        std::env::set_var("MAKIATTO_CI_MODE", "1");
    });
}

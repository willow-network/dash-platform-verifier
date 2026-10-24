// Builds the vendored sph X11 reference code (core/x11, from dashpay/rs-x11-hash). In the SP1
// guest it is compiled freestanding (clang, see .cargo/config.toml) against x11/sysroot's headers.
fn main() {
    println!("cargo:rerun-if-changed=x11");
    let mut cc = cc::Build::new();
    cc.file("x11/x11_hash.c").include("x11").opt_level(2);
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("zkvm") {
        cc.flag("-ffreestanding").flag("-isystem").flag("x11/sysroot");
    }
    cc.compile("dash_x11");
}

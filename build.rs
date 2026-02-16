use std::path::Path;

fn main() {
    println!("cargo:rustc-check-cfg=cfg(embedded_cve_db)");
    println!("cargo:rerun-if-changed=assets/cve.db.zst");

    if Path::new("assets/cve.db.zst").exists() {
        println!("cargo:rustc-cfg=embedded_cve_db");
    }
}

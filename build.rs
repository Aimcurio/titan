fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let root = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    for name in ["f03-fixtures", "f04-fixtures/cases", "f05-fixtures", "f06-fixtures", "f07-fixtures"] {
        std::fs::create_dir_all(root.join(name)).expect("create isolated fixture prerequisites");
    }
}

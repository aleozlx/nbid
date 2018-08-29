use std::process::Command;
use std::path::Path;

fn main() {
    let out_dir = "build_anti-ptrace";
    Command::new("gcc").args(&["-c", "-o", &format!("{}/anti-ptrace.o", out_dir), "src/anti-ptrace.c"])
        .status().unwrap();
    Command::new("ar").args(&["rcs", "libanti_ptrace.a", "anti-ptrace.o"])
        .current_dir(&Path::new(&out_dir))
        .status().unwrap();
    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=anti_ptrace");
}

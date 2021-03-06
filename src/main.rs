// cargo build --release --target x86_64-unknown-linux-musl && strip target/x86_64-unknown-linux-musl/release/nbid 
extern crate regex;
extern crate chrono;

extern { fn anti_ptrace() -> i32; }

use std::process;
use std::env;
use std::fs::File;
use std::collections::HashMap;
use std::io::prelude::*;
use std::panic;
use regex::Regex;
use chrono::prelude::*;

fn ppid(pid: u32) -> Option<u32> {
    let mut f = File::open(&format!("/proc/{}/stat", pid)).ok()?;
    let mut contents = String::new();
    f.read_to_string(&mut contents).ok()?;
    let stat: Vec<&str> = contents.split("\x20").collect();
    // ref: http://man7.org/linux/man-pages/man5/proc.5.html /proc/[pid]/stat
    stat[3].parse().ok()
}

fn cmdline(pid: u32) -> Option<String> {
    let mut f = File::open(&format!("/proc/{}/cmdline", pid)).ok()?;
    let mut contents = String::new();
    f.read_to_string(&mut contents).ok()?;
    Some(contents)
}

fn copy_user_info(facts: &mut HashMap<String, String>, user: &str) {
    if let Some(output) = std::process::Command::new("getent").args(&["passwd", &user]).output().ok() {
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let fields: Vec<&str> = stdout.split(":").collect();
        facts.insert(String::from("uid"), String::from(fields[2]));
        facts.insert(String::from("gid"), String::from(fields[3]));
        facts.insert(String::from("full_name"), String::from(fields[4]));
        facts.insert(String::from("home_dir"), String::from(fields[5]));
    }
    
}

fn stat_notebook(facts: &mut HashMap<String, String>) {
    let mut stat_out;
    if let Some(home_dir) = facts.get("home_dir") {
        if let Some(notebook) = facts.get("notebook") {
            let notebook_path = std::path::Path::new(home_dir).join(notebook);
            let notebook_path = notebook_path.to_str().unwrap();
            if let Some(output) = std::process::Command::new("stat").args(&["-c", "%y", notebook_path]).output().ok() {
                stat_out = String::from_utf8_lossy(&output.stdout).into_owned();
                let len = stat_out.len();
                stat_out.truncate(len - 1); // remove trailing \n
            }
            else { return; }
        }
        else { return; }
    }
    else { return; }
    facts.insert(String::from("last_modified"), stat_out);
}

fn main() {
    panic::set_hook(Box::new(|_info| {}));
    if unsafe {anti_ptrace()} == -1 {
        panic!();
    }

    let ppid = ppid(process::id()).unwrap();
    let ref cmd = cmdline(ppid).unwrap();
    let rule_cmd = Regex::new(r"/dsa/home/(?P<sso>\w+)/.*/kernel-(?P<kernel_id>.*)\.json").unwrap();
    // let rule_url = Regex::new(r"user/(?P<sso>\w+)/notebooks/(?P<notebook>.*)$").unwrap();
    let mut facts = HashMap::new();
    let datetime: DateTime<Local> = Local::now();
    facts.insert(String::from("timestamp"), datetime.format("%Y-%m-%d %H:%M:%S").to_string());
    facts.insert(String::from("pid"), ppid.to_string().to_owned());
    let username;
    if let Some(cmd_caps) = rule_cmd.captures(cmd) {
        username = cmd_caps.name("sso").unwrap().as_str();
        facts.insert(String::from("sso"), username.to_owned());
        facts.insert(String::from("kernel_id"), cmd_caps.name("kernel_id").unwrap().as_str().to_owned());
    }
    else {
        panic!();
    }
    
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let notebook_path = &args[1];
        facts.insert(String::from("notebook"), notebook_path.to_owned());
    }
    if !facts.contains_key("sso_url") {
        copy_user_info(&mut facts, username);
    }
    stat_notebook(&mut facts); // TODO requires home_dir now

    // openssl enc -aes-256-cbc -salt -out .aml-signature -k PASS
    // openssl enc -aes-256-cbc -d -in .aml-signature -k PASS
    let mut ssl = std::process::Command::new("openssl")
        .args(&["enc", "-aes-256-cbc", "-salt", "-out", ".aml-signature", "-k", include_str!("aml-signature.secret")])
        .stdin(std::process::Stdio::piped()).spawn().expect("error: openssl");
        
    let ssl_pipe = ssl.stdin.as_mut().unwrap();
    for (k, v) in facts.iter() {
        // println!("{} {}", k, v);
        ssl_pipe.write(&format!("{} {}\n", k, v).as_bytes()).expect("I/O error");
    }


}

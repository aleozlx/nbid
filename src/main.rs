// cargo build --release --target x86_64-unknown-linux-musl && strip target/x86_64-unknown-linux-musl/release/nbid 
extern crate regex;

extern { fn anti_ptrace() -> i32; }

use std::process;
use std::env;
use std::fs::File;
use std::collections::HashMap;
use std::io::prelude::*;
use regex::Regex;

// TODO strip symbol table.

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

fn main() {
    if unsafe {anti_ptrace()} == -1 {
        println!("Seriously?");
        std::process::exit(0);
    }
    // TODO self check mod 110.
    let ppid = ppid(process::id()).unwrap();
    let ref cmd = cmdline(ppid).unwrap();
    let rule_cmd = Regex::new(r"/dsa/home/(?P<pawprint>\w+)/.*/kernel-(?P<kernel_id>.*)\.json").unwrap();
    let rule_url = Regex::new(r"user/(?P<pawprint>\w+)/notebooks/(?P<notebook>.*)$").unwrap();
    let mut facts = HashMap::new();
    facts.insert(String::from("pid"), ppid.to_string().to_owned());

    if let Some(cmd_caps) = rule_cmd.captures(cmd) {
        facts.insert(String::from("pawprint"), cmd_caps.name("pawprint").unwrap().as_str().to_owned());
        facts.insert(String::from("kernel_id"), cmd_caps.name("kernel_id").unwrap().as_str().to_owned());
    }
    else {
        println!("Don't call me. Go away!");
        std::process::exit(0);
    }
    
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let url = &args[1];
        if let Some(url_caps) = rule_url.captures(url) {
            facts.insert(String::from("pawprint_url"), url_caps.name("pawprint").unwrap().as_str().to_owned());
            facts.insert(String::from("notebook"), url_caps.name("notebook").unwrap().as_str().to_owned());
        }
    }
    println!("<table>");
    println!("<tr><th>Key</th><th>Value</th></tr>");
    for (k, v) in facts.iter() {
        println!("<tr><td>{}</td><td>{}</td></tr>", k, v);
    }
    println!("</table>");

    // last modify stat -c %y nbid_demo.ipynb
}

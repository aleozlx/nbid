// cargo build --release --target x86_64-unknown-linux-musl
extern crate regex;

use std::process;
use std::env;
use std::fs::File;
use std::collections::HashMap;
use std::io::prelude::*;
use regex::Regex;

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
    
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let url = &args[1];
        if let Some(url_caps) = rule_url.captures(url) {
            facts.insert(String::from("pawprint_url"), url_caps.name("pawprint").unwrap().as_str().to_owned());
            facts.insert(String::from("notebook"), url_caps.name("notebook").unwrap().as_str().to_owned());
        }
    }
    else {
        println!("<table>");
        println!("<th><td>Key</td><td>Value</td></tg>");
        for (k, v) in facts.iter() {
            println!("<tr><td>{}</td><td>{}</td></tr>", k, v);
        }
        println!("</table>");
    }
}


use std::env;

mod dns_hero;
use dns_hero::commands::*;

const MSG_HELP: &str = r#"Usage
    help     Print this help message

    daemon   Run the DNS daemon.

    b64      Create base64-wireformat query
             for the following arg.

    explain  Deserialize a base64 packet and
             print its details.

    resolve  Resolve and explain a domain.
             --doh         use DNS Over HTTPS.
             --cb-adult    use CleanBrowsing Adult filter (default)
             --cb-family   use CleanBrowsing Family filter
             --cb-security use CleanBrowsing Security filter
             --cloudflare  use CloudFlare DNS
             --google      use Google DNS"#;

fn print_help() {
    println!("{}", MSG_HELP);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_help();
        return;
    }

    match args[1].as_str() {
        "daemon" => daemon(&args),
        "b64" => b64(&args),
        "explain" => explain(&args),
        "resolve" => resolve(&args),
        _ => print_help(),
    }
}

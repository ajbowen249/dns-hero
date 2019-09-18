extern crate hyper;
extern crate hyper_tls;

use std::fmt::Write;
use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;

use hyper::client::Client;
use hyper::rt::{self, Future, Stream};
use hyper_tls::HttpsConnector;

use super::data::Packet;

pub const CLEAN_BROWSING_SECURITY_URL: &str = "https://doh.cleanbrowsing.org/doh/security-filter";
pub const CLEAN_BROWSING_ADULT_URL:    &str = "https://doh.cleanbrowsing.org/doh/adult-filter";
pub const CLEAN_BROWSING_FAMILY_URL:   &str = "https://doh.cleanbrowsing.org/doh/family-filter";
pub const CLOUDFLARE_URL:              &str = "https://cloudflare-dns.com/dns-query";
pub const GOOGLE_URL:                  &str = "https://dns.google/dns-query";

pub fn resolve_doh(base_url: &String, request_b64: &String) -> Packet {
    let mut full_url = String::new();
    let _ = write!(&mut full_url, "{}?dns={}", base_url, request_b64);

    Packet::init_from_full(get_request_sync(&full_url))
}

fn get_request_sync(url: &String) -> Vec<u8> {
    let (tx, rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = mpsc::channel();
    rt::run(get_request(url).and_then(move |res| {
        tx.send(res).expect("Failed to send result.");
        Ok(())
    }));

    rx.recv().expect("Web request failed.")
}

fn get_request(url: &String) -> impl Future<Item=Vec<u8>, Error=()> {
    let https = HttpsConnector::new(4).expect("TLS initialization failed");
    let client = Client::builder()
        .build::<_, hyper::Body>(https);

    client
        .get(url.parse::<hyper::Uri>().unwrap())
        .and_then(|res| {
            let mut response_receiver = Vec::<u8>::new();
            // The body is a stream, and for_each returns a new Future
            // when the stream is finished, and calls the closure on
            // each chunk of the body
            let _ = res.into_body().for_each(|chunk| {
                let bytes = chunk.into_bytes();
                for byte in bytes {
                    response_receiver.push(byte);
                }
                Ok(())
            }).wait();

            Ok(response_receiver)
        })
        .map_err(|err| {
            eprintln!("Error {}", err);
        })
}

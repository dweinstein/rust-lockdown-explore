extern crate plist;
extern crate glob;
extern crate openssl;
extern crate rustc_serialize;

use plist::Plist;
use std::path::PathBuf;
use std::fs::File;
use glob::glob;
use openssl::crypto::hash::Type::SHA1;
use rustc_serialize::hex::ToHex;

static RELEVANT: [&'static str; 3] = [
    "DeviceCertificate",
    "HostCertificate",
    "RootCertificate"
];

fn load_plist (path: &PathBuf) {
    let file = File::open(path).unwrap();
    let plist = Plist::read(file).unwrap();

    match plist {
        Plist::Dictionary(dict) => {
            for &key in RELEVANT.iter() {
                match dict.get(key) {
                    Some(&Plist::Data(ref data)) => read_pem(data),
                    _ => ()
                }
            }
        },
        _ => ()
    }
}

fn read_pem (data: &Vec<u8>) {
    let cert = openssl::x509::X509::from_pem(data)
        .ok().expect("Failed to load PEM");
    let fingerprint = cert.fingerprint(SHA1).unwrap();
    let not_before = cert.not_before();
    let not_after = cert.not_after();
    println!("fingerprint={}", fingerprint.to_hex());
    println!("notBefore={}", not_before);
    println!("notAfter={}", not_after);
}


fn main() {
    for entry in glob("/var/db/lockdown/*.plist").expect("Failed to read glob pattern") {
        match entry {
            Ok(path) => load_plist(&path),
            Err(e)   => println!("{:?}", e),
        }
    }

}

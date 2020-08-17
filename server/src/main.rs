use trust_dns_server::authority::{MessageRequest, MessageResponseBuilder};
use std::net::{UdpSocket, Ipv4Addr};
use trust_dns_server::proto::serialize::binary::{BinDecoder, BinDecodable, BinEncoder};
use trust_dns_server::proto::op::Header;
use trust_dns_server::proto::rr::{Record, IntoName, RData};
use trust_dns_server::proto::rr::record_type::RecordType::A;

fn handle_message(message: &[u8], response_encoder: &mut BinEncoder) {
    //let str = str::from_utf8(&buffer).unwrap();
    //println!("Handling message of size {}, message {}", buffer.len(), str);
    let mut bin_decoder = BinDecoder::new(&message);
    let request = MessageRequest::read(&mut bin_decoder).unwrap();
    for query in request.queries() {
        println!("Query: {:?}", query);
    }

    let builder = MessageResponseBuilder::new(Some(request.raw_queries()));
    let mut header = Header::new();
    header.set_id(request.id()).set_answer_count(1);

    let response_ip = Ipv4Addr::new(1, 2, 3, 4);
    let name = request.queries()[0].name().into_name().unwrap();

    let mut rr = Record::with(name, A, 1000);
    rr.set_rdata(RData::A(response_ip));
    let rrs = [rr];

    let response = builder.build(header, &rrs, Vec::new(), Vec::new(), Vec::new());
    response.destructive_emit(response_encoder).unwrap();
}

fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:10053")?;
    let mut buffer = [0 as u8; 1024];
    loop {
        let (bytes_read, source) = socket.recv_from(&mut buffer)?;
        println!("From {}: Message with {} bytes", source, bytes_read);

        let mut response: Vec<u8> = Vec::new();
        let mut encoder = BinEncoder::new( &mut response);

        handle_message(&buffer[0..bytes_read], &mut encoder);
        let bytes_sent = socket.send_to(response.as_slice(), source)?;
        println!("To {}: Sent {} bytes.", source, bytes_sent);

    }
}

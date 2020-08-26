#[cfg(test)]
mod message_tests {
    use trust_dns_proto::rr::domain::Label;
    use trust_dns_proto::rr::Name;
    use trust_dns_proto::serialize::binary::{BinEncoder, BinEncodable, BinDecoder, BinDecodable};

    use crate::decode::MessageDecoder;
    use crate::encode::MessageEncoder;
    use crate::message::Message;

    fn messages_to_test() -> Vec<Message> {
        vec![
            Message::Announcement {
                host: "database".to_string(),
                file_name: "secrets.txt".to_string(),
                rnd_nr: 1234,
            },
            Message::Data {
                id: 2,
                data: vec![1, 2, 3, 4, 5],
            },
            Message::Finish {
                rnd_nr: 1234
            }
        ]
    }

    fn write_read(m: trust_dns_proto::op::Message) -> trust_dns_proto::op::Message {
        let mut buffer: Vec<u8> = Vec::new();
        let mut bin_encoder = BinEncoder::new(&mut buffer);
        m.emit(&mut bin_encoder).unwrap();
        let mut bin_decoder = BinDecoder::new(&mut buffer);
        trust_dns_proto::op::Message::read(&mut bin_decoder).unwrap()
    }

    #[test]
    fn test_symmetric() {
        let label = Label::from_utf8("magic").unwrap();
        let subdomain = Name::from_utf8("extract.de.").unwrap();
        let encoder = MessageEncoder::new(label.clone(), subdomain.clone());
        let decoder = MessageDecoder::new(label, subdomain);

        for message in messages_to_test() {
            // println!("message = {:?}", message);
            let dns_message = encoder.encode(message.clone());
            let dns_message = write_read(dns_message);
            // println!("dns_message =  ${:?}", dns_message);
            let message2 = decoder.decode(&dns_message).unwrap();
            // println!("message2 = {:?}", message2);
            assert_eq!(message, message2);
        }
    }
}


#[cfg(test)]
mod message_response_tests {
    use std::str::FromStr;

    use trust_dns_proto::rr::{Name, RData, Record};

    use crate::message::{DataResponse, FinishResponse, MessageResponse};

    fn messages_to_test() -> Vec<MessageResponse> {
        vec![
            MessageResponse::Announcement { rnd_nr: 1234, next_id: 42 },
            MessageResponse::Data { response: DataResponse::Resend },
            MessageResponse::Data { response: DataResponse::Acknowledge { next_id: 43 } },
            MessageResponse::Finish { response: FinishResponse::Resend },
            MessageResponse::Finish { response: FinishResponse::Acknowledge { rnd_nr: 1234 } }
        ]
    }

    fn create_dns_message(r_data: RData) -> trust_dns_proto::op::Message {
        let mut message = trust_dns_proto::op::Message::new();
        let name = Name::from_str("test.de").unwrap();
        message.add_answer(Record::from_rdata(name, 120, r_data));
        message
    }


    #[test]
    fn test_symmetric() {
        for message in messages_to_test() {
            let r_data = message.clone().encode();
            let dns_message = create_dns_message(r_data);
            let message2 = MessageResponse::decode(&dns_message);
            assert_eq!(message, message2.unwrap());
        }
    }
}
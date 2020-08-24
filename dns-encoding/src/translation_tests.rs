
#[cfg(test)]
mod message_response_tests {
    use crate::encode::MessageResponseEncoder;
    use crate::decode::MessageResponseDecoder;
    use crate::message::{MessageResponse, DataResponse, FinishResponse};
    use trust_dns_proto::rr::{RData, Record, Name};
    use std::str::FromStr;

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
    fn test_symetric() {
        let encoder = MessageResponseEncoder::new();
        let decoder = MessageResponseDecoder::new();
        for message in messages_to_test() {
            let r_data = encoder.encode(message.clone());
            let dns_message = create_dns_message(r_data);
            let message2 = decoder.decode(&dns_message);
            assert_eq!(message, message2.unwrap());

        }
    }
}
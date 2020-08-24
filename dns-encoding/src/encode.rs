use trust_dns_proto::rr::domain::Label;
use trust_dns_proto::rr::{Name, RData};
use crate::message::{Message, ANNOUNCEMENT_ID, FINISH_ID, MessageResponse, DataResponse, FinishResponse};
use trust_dns_proto::op::Query;
use std::net::Ipv4Addr;
use std::str::FromStr;

struct MessageEncoder {
    magic_nr: Label,
    sub_domain: Name,
}

impl MessageEncoder {

    fn new(magic_nr: Label, sub_domain: Name) -> MessageEncoder {
        MessageEncoder { magic_nr, sub_domain }
    }

    fn encode(message: Message) -> trust_dns_proto::op::Message {
        let mut dns_message = trust_dns_proto::op::Message::new();

        let (id, name) = match message {
            Message::Announcement { host, file_name, rnd_nr } => {
                let labels = vec![host, file_name, rnd_nr.to_string()];
                (ANNOUNCEMENT_ID, Name::from_labels(labels).unwrap())
            },
            Message::Data { id, data } => {
                (id, Name::from_labels(vec![data]).unwrap())
            },
            Message::Finish { rnd_nr } => {
                let labels = vec![rnd_nr.to_string()];
                (FINISH_ID, Name::from_labels(labels).unwrap())
            },
        };

        dns_message.set_id(id);

        let mut query = Query::new();
        query.set_name(name);
        dns_message.add_query(query);

        dns_message
    }

}

pub struct MessageResponseEncoder {}

impl MessageResponseEncoder {

    pub fn new() -> MessageResponseEncoder {
        MessageResponseEncoder{}
    }

    pub fn encode(&self, response: MessageResponse) -> RData {
        match response {
            MessageResponse::Announcement { rnd_nr, next_id } => {
                let name = Name::from_str(format!("a.{}.{}", rnd_nr, next_id).as_str()).unwrap();
                RData::CNAME(name)
            },
            MessageResponse::Data { response } => {
                RData::A(match response {
                    DataResponse::Resend => {
                        Ipv4Addr::new(1, 1, 1, 1)
                    },
                    DataResponse::Acknowledge { next_id } => {
                        let next_id_bytes = next_id.to_le_bytes();
                        Ipv4Addr::new(2, 2, next_id_bytes[0], next_id_bytes[1])
                    },
                })
            },
            MessageResponse::Finish { response } => {
                match response {
                    FinishResponse::Resend => {
                        let name = Name::from_str("f.r").unwrap();
                        RData::CNAME(name)
                    },
                    FinishResponse::Acknowledge { rnd_nr } => {
                        let name = Name::from_str(format!("f.a.{}", rnd_nr).as_str()).unwrap();
                        RData::CNAME(name)
                    },
                }
            },
        }
    }

}
use trust_dns_proto::rr::domain::Label;
use trust_dns_proto::rr::Name;
use crate::message::{Message, ANNOUNCEMENT_ID, FINISH_ID};
use trust_dns_proto::op::Query;
use base32::Alphabet;

pub struct MessageEncoder {
    magic_nr: Label,
    sub_domain: Name,
}

impl MessageEncoder {

    pub fn new(magic_nr: Label, sub_domain: Name) -> MessageEncoder {
        MessageEncoder { magic_nr, sub_domain }
    }

    pub fn encode(&self, message: Message) -> trust_dns_proto::op::Message {
        let mut dns_message = trust_dns_proto::op::Message::new();

        let mut name = Name::new().append_label(&self.magic_nr).unwrap();

        let (id, payload_name) = match message {
            Message::Announcement { host, file_name, rnd_nr } => {
                let encoded_filename = base32::encode(Alphabet::Crockford, file_name.as_bytes());
                let labels = vec![host, encoded_filename, rnd_nr.to_string()];
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

        name = name.append_name(&payload_name);
        name = name.append_name(&self.sub_domain);


        let mut query = Query::new();
        query.set_name(name);

        dns_message.set_id(id);
        dns_message.add_query(query);
        dns_message
    }

}

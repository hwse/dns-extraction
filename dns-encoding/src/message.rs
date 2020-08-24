pub type Id = u16;

#[derive(Debug, Eq, PartialEq)]
pub enum Message {
    Announcement {
        host: String,
        file_name: String,
        rnd_nr: u16,
    },
    Data {
        id: Id,
        data: Vec<u8>,
    },
    Finish {
        rnd_nr: u16,
    },
}

impl Message {
    pub fn initial(host: String, file_name: String, rnd_nr: u16) -> Message {
        Message::Announcement {
            host,
            file_name,
            rnd_nr,
        }
    }

    fn parse_announcement(dns_message: trust_dns_proto::op::Message) -> Message {
        assert_eq!(dns_message.query_count(), 1);
        let name = &dns_message.queries()[0].name();
        assert_eq!(name.len(), 3);

        Message::Announcement {
            host: name[0].to_ascii(),
            file_name: name[1].to_ascii(),
            rnd_nr: name[2].to_ascii().parse().expect("expected number"),
        }
    }

    pub fn from_dns(dns_message: trust_dns_proto::op::Message) -> Message {
        match dns_message.id() {
            0 => Message::parse_announcement(dns_message),
            1 => Message::Finish { rnd_nr: 0 },
            _ => Message::Data { id: dns_message.id(), data: vec![] },
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum DataResponse {
    Resend,
    Acknowledge { next_id: Id },
}

#[derive(Debug, Eq, PartialEq)]
pub enum FinishResponse {
    Resend,
    Acknowledge { rnd_nr: u16 },
}

#[derive(Debug, Eq, PartialEq)]
pub enum MessageResponse {
    Announcement {
        rnd_nr: u16,
        next_id: Id,
    },
    Data {
        response: DataResponse
    },
    Finish {
        response: FinishResponse
    },
}

use trust_dns_proto::rr::domain::Label;
use trust_dns_proto::rr::{Name, RData};

use crate::message::{Id, Message, MessageResponse, DataResponse, FinishResponse};
use crate::decode::MessageResponseDecoderError::{UnsupportedDnsType, InvalidName};
use std::net::Ipv4Addr;

const ANNOUNCEMENT_ID: u16 = 0;
const FINISH_ID: u16 = 1;

pub struct MessageDecoder {
    magic_nr: Label,
    sub_domain: Name,
    minimum_subdomains: usize,
}

enum MessageDecoderError {
    /** The DNS message contained no queries */
    NoQueries,
    /** The DNS messages contained to few labels */
    TooFewLabels,
    /** The first label was not the magic nr */
    NoMagicNr,
    /** Wrong Subdomain */
    WrongSubdomain,

    ExpectedNrLabel,
}

pub type MessageResult = Result<Message, MessageDecoderError>;

impl MessageDecoder {
    fn new(magic_nr: Label, sub_domain: Name) -> MessageDecoder {
        let minimum_subdomains =
            1 + // one for magic nr
                sub_domain.len() + // subdomains
                1; // at least one to transmit payload
        MessageDecoder { magic_nr, sub_domain, minimum_subdomains }
    }

    pub fn decode(&self, dns_message: &trust_dns_proto::op::Message) -> Result<Message, MessageDecoderError> {
        let payload = self.check_and_prepare_message(&dns_message)?;
        match dns_message.id() {
            ANNOUNCEMENT_ID => self.parse_announcement(payload),
            FINISH_ID => self.parse_finish(payload),
            _ => self.parse_data(payload, dns_message.id()),
        }
    }

    ///
    /// Check if this is a valid message and return the payload
    ///
    fn check_and_prepare_message(&self, dns_message: &trust_dns_proto::op::Message) -> Result<Vec<Label>, MessageDecoderError> {
        if dns_message.query_count() < 1 {
            return Err(MessageDecoderError::NoQueries);
        }

        let query = &dns_message.queries()[0];
        let q_name = query.name();
        if q_name.len() < self.minimum_subdomains {
            return Err(MessageDecoderError::TooFewLabels);
        }

        if q_name[0] != self.magic_nr {
            return Err(MessageDecoderError::NoMagicNr);
        }

        let dns_iter = q_name.iter()
            .rev()
            .take(self.sub_domain.len());
        let sub_domain_iter = self.sub_domain
            .iter()
            .rev();
        if !dns_iter.eq(sub_domain_iter) {
            return Err(MessageDecoderError::WrongSubdomain);
        }

        let end_index = q_name.len() - self.sub_domain.len();
        let mut result = Vec::with_capacity(end_index - 1);
        for i in 1..end_index {
            result.push(q_name[i].clone());
        }
        Ok(result)
    }

    fn parse_announcement(&self, payload: Vec<Label>) -> Result<Message, MessageDecoderError> {
        if payload.len() < 3 {
            return Err(MessageDecoderError::TooFewLabels)
        }
        let host = payload[0].to_ascii();
        let file_name = payload[1].to_ascii();
        let rnd_nr: u16 = payload[2].to_ascii()
            .parse()
            .map_err(|e| MessageDecoderError::ExpectedNrLabel)?;
        Ok(Message::Announcement { host, file_name, rnd_nr })
    }


    fn parse_data(&self, payload: Vec<Label>, id: Id) -> Result<Message, MessageDecoderError> {
        if payload.len() < 1 {
            return Err(MessageDecoderError::TooFewLabels);
        }
        let data = payload[0].as_bytes()
            .iter()
            .map(|x| *x)
            .collect();
        Ok(Message::Data { id, data })
    }

    fn parse_finish(&self, payload: Vec<Label>) -> Result<Message, MessageDecoderError> {
        if payload.len() < 1 {
            return Err(MessageDecoderError::TooFewLabels);
        }
        let rnd_nr: u16 = payload[2].to_ascii()
            .parse()
            .map_err(|e| MessageDecoderError::ExpectedNrLabel)?;
        Ok(Message::Finish { rnd_nr })
    }
}

#[derive(Debug)]
pub enum MessageResponseDecoderError {
    NoAnswers,
    UnsupportedDnsType,
    InvalidIpv4,
    InvalidName,
    TooFewLabels,
    InvalidNumber,
}

pub struct MessageResponseDecoder {
}

impl MessageResponseDecoder {

    pub fn new() -> MessageResponseDecoder {
        MessageResponseDecoder {}
    }

    fn parse_ip(&self, ip: &Ipv4Addr) -> Result<MessageResponse, MessageResponseDecoderError> {
        let bytes = ip.octets();
        if bytes[0] == 1 && bytes[1] == 1 {
            Ok(MessageResponse::Data { response: DataResponse::Resend })
        } else if bytes[0] == 2 && bytes[1] == 2 {
            let next_id = u16::from_le_bytes([bytes[2], bytes[3]]);
            Ok(MessageResponse::Data { response: DataResponse::Acknowledge { next_id } })
        } else {
            Err(MessageResponseDecoderError::InvalidIpv4)
        }
    }

    fn parse_cname(&self, cname: &Name) -> Result<MessageResponse, MessageResponseDecoderError> {
        if cname.len() < 2 {
            return Err(MessageResponseDecoderError::TooFewLabels)
        }
        let message_type = &cname[0].to_ascii();
        match message_type.as_str() {
            "a" => {
                if cname.len() < 3 {
                    return Err(MessageResponseDecoderError::TooFewLabels);
                }
                let rnd_nr = cname[1].to_ascii().parse().map_err(|e| MessageResponseDecoderError::InvalidNumber)?;
                let next_id = cname[2].to_ascii().parse().map_err(|e| MessageResponseDecoderError::InvalidNumber)?;

                Ok(MessageResponse::Announcement { rnd_nr, next_id })
            },
            "f" => {
                let finish_type = cname[1].to_ascii();
                match finish_type.as_str() {
                    "r" => Ok(MessageResponse::Finish { response: FinishResponse::Resend }),
                    "a" => {
                        if cname.len() < 3 {
                            return Err(MessageResponseDecoderError::TooFewLabels)
                        }
                        let rnd_nr = cname[2].to_ascii().parse().map_err(|e| MessageResponseDecoderError::InvalidNumber)?;
                        Ok(MessageResponse::Finish { response: FinishResponse::Acknowledge { rnd_nr } })
                    },
                    _ => Err(MessageResponseDecoderError::InvalidName)
                }
            },
            _ => Err(MessageResponseDecoderError::InvalidName)
        }
    }

    pub fn decode(&self, message: &trust_dns_proto::op::Message) -> Result<MessageResponse, MessageResponseDecoderError> {
        if message.answers().is_empty() {
            return Err(MessageResponseDecoderError::NoAnswers)
        }
        let record = &message.answers()[0];
        let x = match record.rdata() {
            RData::A(ip) => self.parse_ip(ip),
            RData::CNAME(cname) => self.parse_cname(cname),
            _ => Err(MessageResponseDecoderError::UnsupportedDnsType)
        };
        x
    }

}
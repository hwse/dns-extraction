use trust_dns_proto::rr::domain::Label;
use trust_dns_proto::rr::Name;

use crate::message::{Id, Message};
use base32::Alphabet;

const ANNOUNCEMENT_ID: u16 = 0;
const FINISH_ID: u16 = 1;

pub struct MessageDecoder {
    magic_nr: Label,
    sub_domain: Name,
    minimum_subdomains: usize,
}

#[derive(Debug)]
pub enum MessageDecoderError {
    /** The DNS message contained no queries */
    NoQueries,
    /** The DNS messages contained to few labels */
    TooFewLabels,
    /** The first label was not the magic nr */
    NoMagicNr,
    /** Wrong Subdomain */
    WrongSubdomain,

    ExpectedNrLabel,

    InvalidBase32,
}

pub type MessageResult = Result<Message, MessageDecoderError>;

impl MessageDecoder {

    pub fn new(magic_nr: Label, sub_domain: Name) -> MessageDecoder {
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

    pub fn decode_base32(data: &str) -> Result<Vec<u8>, MessageDecoderError> {
        match base32::decode(Alphabet::Crockford, &data) {
            None => { Err(MessageDecoderError::InvalidBase32,) },
            Some(v) => Ok(v)
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

        let sub_domain_len = self.sub_domain.num_labels();

        let dns_iter= q_name.iter()
            .rev()
            .take(sub_domain_len as usize);
        let sub_domain_iter = self.sub_domain
            .iter()
            .rev();
        if !dns_iter.eq(sub_domain_iter) {
            return Err(MessageDecoderError::WrongSubdomain);
        }

        let end_index =  (q_name.num_labels() - self.sub_domain.num_labels()) as usize;
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
        let encoded_str = payload[1].to_ascii();
        let file_name_bytes  = MessageDecoder::decode_base32(encoded_str.as_str())?;
        let file_name = String::from_utf8(file_name_bytes).unwrap();

        let rnd_nr: u16 = payload[2].to_ascii()
            .parse()
            .map_err(|_| MessageDecoderError::ExpectedNrLabel)?;
        Ok(Message::Announcement { host, file_name, rnd_nr })
    }


    fn parse_data(&self, payload: Vec<Label>, id: Id) -> Result<Message, MessageDecoderError> {
        if payload.is_empty() {
            return Err(MessageDecoderError::TooFewLabels);
        }
        let data = payload[0].as_bytes()
            .iter()
            .copied()
            .collect();
        Ok(Message::Data { id, data })
    }

    fn parse_finish(&self, payload: Vec<Label>) -> Result<Message, MessageDecoderError> {
        if payload.is_empty() {
            return Err(MessageDecoderError::TooFewLabels);
        }
        let rnd_nr: u16 = payload[0].to_ascii()
            .parse()
            .map_err(|_| MessageDecoderError::ExpectedNrLabel)?;
        Ok(Message::Finish { rnd_nr })
    }
}

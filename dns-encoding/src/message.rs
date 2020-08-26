use trust_dns_proto::rr::{RData, Name};
use std::net::Ipv4Addr;
use std::str::FromStr;

pub type Id = u16;

pub const ANNOUNCEMENT_ID: Id = 0;
pub const FINISH_ID: Id = 1;

#[derive(Debug, Eq, PartialEq, Clone)]
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
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum DataResponse {
    Resend,
    Acknowledge { next_id: Id },
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum FinishResponse {
    Resend,
    Acknowledge { rnd_nr: u16 },
}

#[derive(Debug, Eq, PartialEq, Clone)]
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


#[derive(Debug)]
pub enum MessageResponseDecoderError {
    NoAnswers,
    UnsupportedDnsType,
    InvalidIpv4,
    InvalidName,
    TooFewLabels,
    InvalidNumber,
}



impl MessageResponse {

    pub fn encode(self) -> RData {
        match self {
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

    fn parse_ip(ip: &Ipv4Addr) -> Result<MessageResponse, MessageResponseDecoderError> {
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

    fn parse_cname(cname: &Name) -> Result<MessageResponse, MessageResponseDecoderError> {
        if cname.len() < 2 {
            return Err(MessageResponseDecoderError::TooFewLabels)
        }
        let message_type = &cname[0].to_ascii();
        match message_type.as_str() {
            "a" => {
                if cname.len() < 3 {
                    return Err(MessageResponseDecoderError::TooFewLabels);
                }
                let rnd_nr = cname[1].to_ascii().parse().map_err(|_| MessageResponseDecoderError::InvalidNumber)?;
                let next_id = cname[2].to_ascii().parse().map_err(|_| MessageResponseDecoderError::InvalidNumber)?;

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
                        let rnd_nr = cname[2].to_ascii().parse().map_err(|_| MessageResponseDecoderError::InvalidNumber)?;
                        Ok(MessageResponse::Finish { response: FinishResponse::Acknowledge { rnd_nr } })
                    },
                    _ => Err(MessageResponseDecoderError::InvalidName)
                }
            },
            _ => Err(MessageResponseDecoderError::InvalidName)
        }
    }

    pub fn decode(message: &trust_dns_proto::op::Message) -> Result<MessageResponse, MessageResponseDecoderError> {
        if message.answers().is_empty() {
            return Err(MessageResponseDecoderError::NoAnswers)
        }
        let record = &message.answers()[0];
        match record.rdata() {
            RData::A(ip) => Self::parse_ip(ip),
            RData::CNAME(cname) => Self::parse_cname(cname),
            _ => Err(MessageResponseDecoderError::UnsupportedDnsType)
        }
    }
}
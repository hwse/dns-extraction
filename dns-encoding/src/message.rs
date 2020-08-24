pub type Id = u16;

pub const ANNOUNCEMENT_ID: Id = 1;
pub const FINISH_ID: Id = 2;

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

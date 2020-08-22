use crate::message::{Message, MessageResponse, Id, DataResponse};

const SLICE_SIZE: usize = 20;

struct TransmissionState {
    host: String,
    file_name: String,
    data: Vec<u8>,
    index: usize,
    last_id: Id,
}

impl TransmissionState {

    fn new(host: String, file_name: String, data: Vec<u8>) -> TransmissionState {
        TransmissionState { host, file_name, data, index: 0, last_id: 0 }
    }

    fn initial_message(&self) -> Message {
        Message::initial(self.host.clone(), self.file_name.clone())
    }

    fn next_data_message(&self, next_id: Id) -> Message {
        let mut chunk = Vec::with_capacity(SLICE_SIZE);

        let slice = &self.data[self.index..(self.index + SLICE_SIZE)];
        chunk.copy_from_slice(&slice);
        Message::Data {
            id: next_id,
            data: chunk,
        }
    }

    fn handle_response(&mut self, response: MessageResponse) -> Option<Message> {
        match response {
            MessageResponse::Announcement { rnd_nr, next_id } => {
                Some(self.next_data_message(next_id))
            }
            MessageResponse::Data { response } => {
                match response {
                    DataResponse::Resend => {
                        Some(self.next_data_message(self.last_id))
                    }
                    DataResponse::Acknowledge { next_id } => {
                        self.index += SLICE_SIZE;
                        Some(self.next_data_message(next_id))
                    }
                }
            }
            MessageResponse::Finish { response } => {
                None
            }
        }
    }
}
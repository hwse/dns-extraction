use crate::message::{Message, MessageResponse, Id, DataResponse, FinishResponse};
use std::cmp::min;


pub struct TransmissionState {
    host: String,
    file_name: String,
    data: Vec<u8>,
    slice_size: usize,
    index: usize,
    last_id: Id,
    random_nr: u16,
}

impl TransmissionState {
    pub fn new(host: String, file_name: String, data: Vec<u8>, slice_size: usize) -> TransmissionState {
        assert!(slice_size > 0);
        let random_nr = rand::random();
        TransmissionState { host, file_name, data, slice_size, index: 0, last_id: 0, random_nr }
    }

    pub fn initial_message(&self) -> Message {
        Message::initial(self.host.clone(), self.file_name.clone(), self.random_nr)
    }

    fn next_data_message(&self, next_id: Id) -> Message {
        let start_index = self.index;
        let end_index = min(self.index + self.slice_size, self.data.len());
        let chunk_size = end_index - start_index;

        let mut chunk = vec![0; chunk_size];
        let slice = &self.data[start_index..end_index];

        // println!("slice = {:?}", slice);
        chunk.copy_from_slice(&slice);

        Message::Data {
            id: next_id,
            data: chunk,
        }
    }

    fn resend_last_message(&self) -> Message {
        self.next_data_message(self.last_id)
    }

    fn progress_to_next_message(&mut self, next_id: Id) -> Message {
        // last message was received -> progress to next chunk
        self.index += self.slice_size;
        if self.index >= self.data.len() {
            return Message::Finish { id: next_id, rnd_nr: self.random_nr }
        }
        self.next_data_message(next_id)
    }

    pub fn handle_response(&mut self, response: MessageResponse) -> Option<Message> {
        match response {
            MessageResponse::Announcement { rnd_nr, next_id } => {
                Some(self.next_data_message(next_id))
            }
            MessageResponse::Data { response } => {
                match response {
                    DataResponse::Resend => {
                        Some(self.resend_last_message())
                    }
                    DataResponse::Acknowledge { next_id } => {

                        Some(self.progress_to_next_message(next_id))
                    }
                }
            }
            MessageResponse::Finish { response } => {
                match response {
                    FinishResponse::Resend => { panic!("TODO: implement resend") },
                    FinishResponse::Acknowledge { rnd_nr } => None,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::FinishResponse;

    #[test]
    fn test_good_case() {
        let mut state = TransmissionState::new(
            "host".to_string(),
            "file.txt".to_string(),
            vec![1, 2, 3, 4, 5, 6, 7],
            3,
        );
        let message0 = state.initial_message();
        let client_rnd_nr = match message0 {
            Message::Announcement { host, file_name, rnd_nr } => {
                assert_eq!(state.host, host);
                assert_eq!(state.file_name, file_name);
                rnd_nr
            }
            _ => panic!("Expected an announcement")
        };
        let response0 = MessageResponse::Announcement { rnd_nr: client_rnd_nr, next_id: 2 };
        let message1 = state.handle_response(response0).expect("Expected a next message");
        match message1 {
            Message::Data { id, data } => {
                assert_eq!(2, id);
                assert_eq!(vec![1, 2, 3], data);
            }
            _ => { panic!("Expected a data message.") }
        }

        let response1 = MessageResponse::Data { response: DataResponse::Acknowledge { next_id: 3 } };
        match state.handle_response(response1).expect("Expected another message") {
            Message::Data { id, data } => {
                assert_eq!(3, id);
                assert_eq!(vec![4, 5, 6], data);
            }
            _ => panic!("Expected a data message.")
        }

        let response2 = MessageResponse::Data { response: DataResponse::Acknowledge { next_id: 4 } };
        match state.handle_response(response2).expect("Expected another message") {
            Message::Data { id, data } => {
                assert_eq!(4, id);
                assert_eq!(vec![7], data);
            }
            _ => panic!("Expected a data message.")
        }

        let response3 = MessageResponse::Data { response: DataResponse::Acknowledge { next_id: 5 } };
        match state.handle_response(response3).expect("Expected another message") {
            Message::Finish { id, rnd_nr } => {
                assert_eq!(5, id);
                assert_eq!(client_rnd_nr, rnd_nr);
            },
            _ => panic!("Expected a Finish message")
        }

        let response4 = MessageResponse::Finish { response: FinishResponse::Acknowledge { rnd_nr: client_rnd_nr }};
        assert_eq!(None, state.handle_response(response4));
    }
}

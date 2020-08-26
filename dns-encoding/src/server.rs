use crate::message::{DataResponse, FinishResponse, Id, Message, MessageResponse};

#[derive(Debug)]
pub struct ServerState {
    states: Vec<TransmissionState>,
    finished_states: Vec<TransmissionState>,
    id_generator: IdGenerator,
}

#[derive(Debug)]
pub enum ServerError {
    UnknownId { id: Id },
    UnknownRndNr { rnd_nr: u16 },
}

impl ServerState {
    pub fn new() -> ServerState {
        ServerState {
            states: Vec::new(),
            finished_states: Vec::new(),
            id_generator: IdGenerator::new(),
        }
    }

    pub fn handle_message(&mut self, message: Message) -> Result<MessageResponse, ServerError> {
        match message {
            Message::Announcement { host, file_name, rnd_nr } => {
                let next_id = self.id_generator.next_id();
                let state = TransmissionState::new(
                    rnd_nr, host, file_name, next_id);
                self.states.push(state);
                Ok(MessageResponse::Announcement { rnd_nr, next_id })
            }
            Message::Data { id, mut data } => {
                let mut state = ServerState::find_state(&mut self.states, id)?;
                state.data.append(&mut data);

                let next_id = self.id_generator.next_id();
                state.expected_id = next_id;
                Ok(MessageResponse::Data {
                    response: DataResponse::Acknowledge {
                        next_id
                    }
                })
            }
            Message::Finish { rnd_nr } => {
                let state = self.pop_state(rnd_nr)?;
                self.finished_states.push(state);
                Ok(MessageResponse::Finish {
                    response: FinishResponse::Acknowledge { rnd_nr }
                })
            }
        }
    }

    fn find_state(states: &mut Vec<TransmissionState>, id: Id) -> Result<&mut TransmissionState, ServerError> {
        let state = states
            .iter_mut()
            .find(|s| s.expected_id == id);
        match state {
            None => Err(ServerError::UnknownId { id }),
            Some(state) => Ok(state),
        }
    }

    fn pop_state(&mut self, rnd_nr: u16) -> Result<TransmissionState, ServerError> {
        let x = self.states
            .iter()
            .enumerate()
            .find(|(_i, state)| state.rdm_nr == rnd_nr);
        match x {
            None => Err(ServerError::UnknownRndNr { rnd_nr }),
            Some((i, _s)) => {
                Ok(self.states.remove(i))
            }
        }
    }
}


#[cfg(test)]
mod server_state_tests {
    use super::*;

    #[test]
    fn test_good_case() {
        let mut server_state = ServerState::new();

        let message0 = Message::Announcement {
            host: "db-server".to_string(),
            file_name: "passwords.txt".to_string(),
            rnd_nr: 23523,
        };

        let response0 = server_state.handle_message(message0)
            .expect("expected a response");
        let next_id = match response0 {
            MessageResponse::Announcement { rnd_nr, next_id } => {
                assert_eq!(23523, rnd_nr);
                next_id
            }
            _ => panic!("Expected an announcement response")
        };

        let message1 = Message::Data { id: next_id, data: vec![1, 2, 3] };
        let response1 = server_state.handle_message(message1)
            .expect("expected an response");

        match response1 {
            MessageResponse::Data { response } => {
                match response {
                    DataResponse::Acknowledge { next_id: _ } => { }
                    DataResponse::Resend => { panic!("Expected an acknowledge") }
                }
            }
            _ => panic!("Expected an data response")
        };

        let message2 = Message::Finish { rnd_nr: 23523 };
        let response2 = server_state.handle_message(message2)
            .expect("expected an response");
        match response2 {
            MessageResponse::Finish { response } => {
                match response {
                    FinishResponse::Acknowledge { rnd_nr } => {
                        assert_eq!(23523, rnd_nr);
                    }
                    FinishResponse::Resend => { panic!("Expected an acknowledge") }
                }
            }
            _ => panic!("Expected Finish response")
        }

        assert_eq!(1, server_state.finished_states.len());
    }
}

#[derive(Debug)]
struct TransmissionState {
    rdm_nr: u16,
    expected_id: Id,
    host: String,
    name: String,
    data: Vec<u8>,
}

impl TransmissionState {
    fn new(rdm_nr: u16, host: String, name: String, expected_id: Id) -> TransmissionState {
        TransmissionState {
            rdm_nr,
            expected_id,
            host,
            name,
            data: Vec::new(),
        }
    }
}

const ID_RANGE_START: u16 = 2;

#[derive(Debug)]
pub struct IdGenerator {
    next_id: Id
}

impl IdGenerator {
    pub fn new() -> IdGenerator {
        IdGenerator {
            next_id: ID_RANGE_START
        }
    }

    pub fn next_id(&mut self) -> Id {
        let result = self.next_id;
        if self.next_id == std::u16::MAX {
            self.next_id = ID_RANGE_START
        } else {
            self.next_id += 1;
        }
        result
    }
}


#[cfg(test)]
mod id_generator_tests {
    use super::*;

    #[test]
    fn test_id_generator() {
        let mut generator = IdGenerator::new();
        assert_eq!(2, generator.next_id());
        assert_eq!(3, generator.next_id());
        assert_eq!(4, generator.next_id());

        let mut generator = IdGenerator { next_id: std::u16::MAX };
        assert_eq!(std::u16::MAX, generator.next_id());
        assert_eq!(2, generator.next_id());
        assert_eq!(3, generator.next_id());
    }
}
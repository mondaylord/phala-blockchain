use serde::{Deserialize, Serialize};

use crate::contracts;
use crate::contracts::AccountIdWrapper;
use crate::types::TxRef;
use crate::TransactionStatus;
use secp256k1::{Message, SecretKey};
use sp_core::hashing::blake2_256;
use sp_core::H256 as Hash;
extern crate runtime as chain;
use parity_scale_codec::{Decode, Encode};

use crate::std::collections::BTreeMap;
use crate::std::string::String;
use crate::std::format;
use crate::std::vec::Vec;
use rand::Rng;

type SequenceType = u64;

/// SubstrateKitties contract states.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct SubstrateKitties {
    schrodingers: BTreeMap<String, String>,
    kitties: BTreeMap<String, Kitty>,
    blind_boxes: BTreeMap<String, BlindBox>,
    sequence: SequenceType,
    queue: Vec<KittyTransferData>,
    #[serde(skip)]
    secret: Option<SecretKey>,
    opened_box_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct BlindBox {
    id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Kitty {
    id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Encode, Decode)]
pub struct KittyTransfer {
    dest: AccountIdWrapper,
    kitty_id: Vec<u8>,
    sequence: SequenceType,
}
#[derive(Serialize, Deserialize, Debug, Clone, Encode, Decode)]
pub struct KittyTransferData {
    data: KittyTransfer,
    signature: Vec<u8>,
}
/// The commands that the contract accepts from the blockchain. Also called transactions.
/// Commands are supposed to update the states of the contract.
#[derive(Serialize, Deserialize, Debug)]
pub enum Command {
    /// Pack the kitties into the corresponding blind boxes
    Pack {},
    Open {
        blind_box_id: String,
    },
}

/// The errors that the contract could throw for some queries
#[derive(Serialize, Deserialize, Debug)]
pub enum Error {
    NotAuthorized,
}

/// Query requests. The end users can only query the contract states by sending requests.
/// Queries are not supposed to write to the contract states.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Request {
    /// Open the specific blind box to see the kitty
    GetKitty {
        blind_box_id: String,
    },
    ObserveBox,
    ObserveKitty,
    PendingKittyTransfer {
        sequence: SequenceType,
    },
}

/// Query responses.
#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    /// Return the kitty_id in the specific blind box
    GetKitty {
        kitty_id: String,
    },
    ObserveBox {
        blind_box: BTreeMap<String, BlindBox>,
    },
    ObserveKitty {
        kitty: BTreeMap<String, Kitty>,
    },
    PendingKittyTransfer {
        transfer_queue_b64: String,
    },
    /// Something wrong happened
    Error(Error),
}

impl SubstrateKitties {
    /// Initializes the contract
    pub fn new(secret: Option<SecretKey>) -> Self {
        let schrodingers = BTreeMap::<String, String>::new();
        let kitties = BTreeMap::<String, Kitty>::new();
        let blind_boxes = BTreeMap::<String, BlindBox>::new();
        let opened_box_id=String::from("");
        SubstrateKitties{
            schrodingers,
            kitties,
            blind_boxes,
            sequence: 0,
            queue: Vec::new(),
            secret,
            opened_box_id,
        }
    }
}

impl contracts::Contract<Command, Request, Response> for SubstrateKitties {
    // Returns the contract id
    fn id(&self) -> contracts::ContractId {
        contracts::SUBSTRATE_KITTIES
    }

    // Handles the commands from transactions on the blockchain. This method doesn't respond.
    fn handle_command(
        &mut self,
        _origin: &chain::AccountId,
        _txref: &TxRef,
        cmd: Command,
    ) -> TransactionStatus {
        match cmd {
            // Handle the `Pack` command with one parameter
            Command::Pack {} => {
                // Create corresponding amount of kitties and blind boxes
                let mut nonce = 1;
                for (kitty_id, _kitty) in self.kitties.iter() {
                    let sender = AccountIdWrapper(_origin.clone());
                    let mut rng = rand::thread_rng();
                    let seed: [u8; 32] = rng.gen();
                    // create blind boxes
                    let raw_data = (seed, &sender, nonce);
                    let rand_hash = blake2_256(&Encode::encode(&raw_data));
                    let random_hash = Hash::from_slice(&rand_hash);
                    nonce += 1;

                    let blind_box_id = format!("{:#x}", random_hash);
                    let new_blind_box = BlindBox {
                        id: blind_box_id.clone(),
                    };
                    println!("New Box: {} is created", blind_box_id.clone());
                    self.schrodingers
                        .insert(blind_box_id.clone(), (*kitty_id).clone());
                    self.blind_boxes.insert(blind_box_id, new_blind_box);
                }
                // Returns TransactionStatus::Ok to indicate a successful transaction
                TransactionStatus::Ok
            }
            Command::Open { blind_box_id } => {
                let sender = AccountIdWrapper(_origin.clone());
                if self.schrodingers.contains_key(&blind_box_id) {
                    let kitty_id = self.schrodingers.get(&blind_box_id).unwrap();
                    self.opened_box_id = blind_box_id;
                    let sequence = self.sequence + 1;
                    let data = KittyTransfer {
                        dest: sender.clone(),
                        kitty_id: (*kitty_id.as_bytes()).to_vec(),
                        sequence,
                    };
                    println!("ready to transfer the kitty to the owner: {:?}", sender);

                    let msg_hash = blake2_256(&Encode::encode(&data));
                    let mut buffer = [0u8; 32];
                    buffer.copy_from_slice(&msg_hash);
                    let message = Message::parse(&buffer);
                    let signature = secp256k1::sign(&message, &self.secret.as_ref().unwrap());
                    println!("signature={:?}", signature);
                    let transfer_data = KittyTransferData {
                        data,
                        signature: signature.0.serialize().to_vec(),
                    };
                    self.queue.push(transfer_data);
                    self.sequence = sequence;
                }
                TransactionStatus::Ok
            }
        }
    }

    // Handles a direct query and responds to the query. It shouldn't modify the contract states.
    fn handle_query(&mut self, _origin: Option<&chain::AccountId>, req: Request) -> Response {
        let inner = || -> Result<Response, Error> {
            match req {
                // Handle the `GetKitty` request
                Request::GetKitty { blind_box_id } => {
                    if blind_box_id == self.opened_box_id {
                        let kitty_id = self.schrodingers.get(&blind_box_id).unwrap();
                        return Ok(Response::GetKitty {
                            kitty_id: (*kitty_id).clone(),
                        });
                    }
                    Err(Error::NotAuthorized)
                }
                Request::ObserveBox => {
                    return Ok(Response::ObserveBox {
                        blind_box: self.blind_boxes.clone(),
                    })
                }
                Request::ObserveKitty => {
                    return Ok(Response::ObserveKitty {
                        kitty: self.kitties.clone(),
                    })
                }
                Request::PendingKittyTransfer { sequence } => {
                    println!("PendingKittyTransfer");
                    let transfer_queue: Vec<&KittyTransferData> = self
                        .queue
                        .iter()
                        .filter(|x| x.data.sequence > sequence)
                        .collect::<_>();

                    Ok(Response::PendingKittyTransfer {
                        transfer_queue_b64: base64::encode(&transfer_queue.encode()),
                    })
                }
            }
        };
        match inner() {
            Err(error) => Response::Error(error),
            Ok(resp) => resp,
        }
    }

    fn handle_event(&mut self, ce: chain::Event) {
        if let chain::Event::pallet_kitties(pe) = ce {
            if let chain::pallet_kitties::RawEvent::Created(account_id, kitty_id) = pe {
                println!("Created Kitty {:} from : ModulePallet", kitty_id);
                let dest = AccountIdWrapper(account_id);
                println!("   dest: {}", dest.to_string());
                let new_kitty_id = format!("{:#x}", kitty_id);
                let new_kitty = Kitty {
                    id: new_kitty_id.clone(),
                };
                println!("New kitty : {} is Added!", new_kitty_id);
                self.kitties.insert(new_kitty_id, new_kitty);
            } else if let chain::pallet_kitties::RawEvent::TransferToChain(
                account_id,
                kitty_id,
                sequence,
            ) = pe
            {
                println!("TransferToChain who: {:?}", account_id);
                let new_kitty_id = format!("{:#x}", kitty_id);
                let transfer_data = KittyTransferData {
                    data: KittyTransfer {
                        dest: AccountIdWrapper(account_id),
                        kitty_id: new_kitty_id.as_bytes().to_vec(),
                        sequence,
                    },
                    signature: Vec::new(),
                };
                println!("transfer data:{:?}", transfer_data);
                self.queue
                    .retain(|x| x.data.sequence > transfer_data.data.sequence);
                println!("queue len: {:}", self.queue.len());
            }
        }
    }
}

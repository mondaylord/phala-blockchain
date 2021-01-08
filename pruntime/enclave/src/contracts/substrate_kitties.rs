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
use crate::std::format;
use crate::std::string::String;
use crate::std::vec::Vec;
use rand::Rng;

type SequenceType = u64;
/// Default owner for the initial blind boxes
const BOX_ID: &str = "PHALA BOX!";

/// SubstrateKitties contract states.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct SubstrateKitties {
    schrodingers: BTreeMap<String, Vec<u8>>,
    /// Use Vec<u8> to represent kitty id
    kitties: BTreeMap<Vec<u8>, Kitty>,
    blind_boxes: BTreeMap<String, BlindBox>,
    /// Record the boxes list which the owners own
    owned_blind_boxes: BTreeMap<String, Vec<String>>,
    sequence: SequenceType,
    queue: Vec<KittyTransferData>,
    #[serde(skip)]
    secret: Option<SecretKey>,
    /// Record the boxes the users opened
    opend_boxes: Vec<String>,
    /// This variable records if there are kitties that not in the boxes
    left_kitties: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct BlindBox {
    id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Kitty {
    id: Vec<u8>,
}

/// These two structs below are used for transferring messages to chain.
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
    /// Open the specific blind box to get the kitty
    Open { blind_box_id: String },
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
    /// Users can require to see the blind boxes list
    ObserveBox,
    /// Users can require to see their owned boxes list
    ObserveOwnedBox,
    /// Users can require to see the kitties which are not in the boxes
    ObserveLeftKitties,
    PendingKittyTransfer {
        sequence: SequenceType,
    },
}

/// Query responses.
#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    ObserveBox {
        blind_box: BTreeMap<String, BlindBox>,
    },
    ObserveOwnedBox {
        owned_box: Vec<String>,
    },
    ObserveLeftKitties {
        kitties: Vec<Vec<u8>>,
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
        let schrodingers = BTreeMap::<String, Vec<u8>>::new();
        let kitties = BTreeMap::<Vec<u8>, Kitty>::new();
        let blind_boxes = BTreeMap::<String, BlindBox>::new();
        let owned_blind_boxes = BTreeMap::<String, Vec<String>>::new();
        SubstrateKitties {
            schrodingers,
            kitties,
            blind_boxes,
            owned_blind_boxes,
            sequence: 0,
            queue: Vec::new(),
            secret,
            opend_boxes: Vec::new(),
            left_kitties: Vec::new(),
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
            // Handle the `Pack` command
            Command::Pack {} => {
                // Create corresponding amount of kitties and blind boxes if there are
                // indeed some kitties that need to be packed
                if !self.left_kitties.is_empty() {
                    let mut nonce = 1;
                    let mut boxes_list = Vec::new();
                    for (kitty_id, _kitty) in self.kitties.iter() {
                        let sender = AccountIdWrapper(_origin.clone());
                        let mut rng = rand::thread_rng();
                        let seed: [u8; 32] = rng.gen();
                        // generate hash number as ID to create blind boxes
                        let raw_data = (seed, &sender, nonce);
                        let hash_data = blake2_256(&Encode::encode(&raw_data));
                        let random_hash = Hash::from_slice(&hash_data);
                        nonce += 1;

                        let blind_box_id = format!("{:#x}", random_hash);
                        let new_blind_box = BlindBox {
                            id: blind_box_id.clone(),
                        };
                        println!("New Box: {:?} is created", blind_box_id.clone());

                        self.schrodingers
                            .insert(blind_box_id.clone(), (*kitty_id).clone());
                        self.blind_boxes.insert(blind_box_id.clone(), new_blind_box);
                        boxes_list.push(blind_box_id);
                    }
                    // After this, new kitties are all packed into boxes
                    self.left_kitties.clear();

                    // For now, boxes all belong to the default 'PHALA_BOX!'
                    self.owned_blind_boxes
                        .insert(String::from(BOX_ID), boxes_list);
                }
                // Returns TransactionStatus::Ok to indicate a successful transaction
                TransactionStatus::Ok
            }
            Command::Open { blind_box_id } => {
                let sender = AccountIdWrapper(_origin.clone());
                // Open the box if it's legal and not opened yet
                if self.schrodingers.contains_key(&blind_box_id)
                    && !self.opend_boxes.contains(&blind_box_id)
                {
                    // Get the kitty based on blind_box_id
                    let kitty_id = self.schrodingers.get(&blind_box_id).unwrap();
                    let sequence = self.sequence + 1;

                    let kitty_id = Hash::from_slice(&kitty_id);

                    // Queue the message to sync the owner transfer info to pallet
                    let data = KittyTransfer {
                        dest: sender.clone(),
                        kitty_id: kitty_id.clone().encode(),
                        sequence,
                    };

                    let mut box_list = self
                        .owned_blind_boxes
                        .get(&String::from(BOX_ID))
                        .unwrap()
                        .clone();
                    // Remove the box from the default owned boxes list
                    box_list.retain(|x| x != &blind_box_id);
                    // Now the original boxes list is decreased by 1
                    self.owned_blind_boxes
                        .insert(String::from(BOX_ID), box_list);

                    self.opend_boxes.push(blind_box_id.clone());

                    // Add this opened box to the new owner
                    let new_owner = sender.to_string();
                    let mut new_owned_list = match self.owned_blind_boxes.get(&new_owner) {
                        Some(_) => self.owned_blind_boxes.get(&new_owner).unwrap().clone(),
                        None => Vec::new(),
                    };
                    new_owned_list.push(blind_box_id);
                    self.owned_blind_boxes.insert(new_owner, new_owned_list);

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
                Request::ObserveBox => {
                    return Ok(Response::ObserveBox {
                        blind_box: self.blind_boxes.clone(),
                    })
                }
                Request::ObserveOwnedBox => {
                    let sender = AccountIdWrapper(_origin.unwrap().clone());
                    let owner = sender.to_string();
                    let owned_boxes = self.owned_blind_boxes.get(&owner);
                    match owned_boxes {
                        Some(_) => {
                            return Ok(Response::ObserveOwnedBox {
                                owned_box: owned_boxes.unwrap().clone(),
                            })
                        }
                        None => {
                            return Ok(Response::ObserveOwnedBox {
                                owned_box: Vec::new(),
                            })
                        }
                    };
                }
                Request::ObserveLeftKitties => {
                    return Ok(Response::ObserveLeftKitties {
                        kitties: self.left_kitties.clone(),
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
            // create_kitties() is called on the chain
            if let chain::pallet_kitties::RawEvent::Created(account_id, kitty_id) = pe {
                println!("Created Kitty {:?} by default owner: Kitty!!!", kitty_id);
                let dest = AccountIdWrapper(account_id);
                println!("   dest: {}", dest.to_string());
                let new_kitty_id = kitty_id.to_fixed_bytes();
                let new_kitty = Kitty {
                    id: new_kitty_id.to_vec(),
                };
                self.kitties.insert(new_kitty_id.to_vec(), new_kitty);
                self.left_kitties.push(new_kitty_id.to_vec());
            } else if let chain::pallet_kitties::RawEvent::TransferToChain(
                account_id,
                kitty_id,
                sequence,
            ) = pe
            {
                // owner transfer info already recieved
                println!("TransferToChain who: {:?}", account_id);
                let new_kitty_id = format!("{:#x}", kitty_id);
                println!("Kitty: {} is transerferred!!", new_kitty_id);
                let transfer_data = KittyTransferData {
                    data: KittyTransfer {
                        dest: AccountIdWrapper(account_id),
                        kitty_id: kitty_id.encode(),
                        sequence,
                    },
                    signature: Vec::new(),
                };
                println!("transfer data:{:?}", transfer_data);
                // message dequeue
                self.queue
                    .retain(|x| x.data.sequence > transfer_data.data.sequence);
                println!("queue len: {:}", self.queue.len());
            }
        }
    }
}

use {
    borsh::{BorshDeserialize, BorshSerialize},
    clap::{value_t, value_t_or_exit},
    solana_clap_utils::{
        input_parsers::*,
        input_validators::*,
        keypair::{CliSignerInfo, DefaultSigner},
        offline::OfflineArgs,
    },
    solana_cli_config::{Config, ConfigInput, CONFIG_FILE},
    solana_client::{client_error, rpc_client::RpcClient},
    solana_sdk::{
        commitment_config::CommitmentConfig,
        instruction::{AccountMeta, Instruction},
        message::Message,
        pubkey,
        pubkey::Pubkey,
        system_program,
        transaction::Transaction,
    },
    std::str::FromStr,
};

const SQUADS_MPL_PROGRAM_ID: Pubkey = pubkey!("SMPLecH534NA9acpos4G6x7uf3LWbCAwZQE9e8ZekMu");

// in lieu of figuring out anchor... write all the shit it probably generates?
#[derive(Debug, BorshDeserialize, BorshSerialize)]
pub struct AnchorWrapper<T: AnchorData> {
    discriminator: [u8; 8],
    data: T,
}

pub trait AnchorData: BorshDeserialize + BorshSerialize {
    const DISCRIMINATOR: [u8; 8];

    fn anchor_wrap(self) -> AnchorWrapper<Self> {
        AnchorWrapper::<Self> {
            discriminator: Self::DISCRIMINATOR,
            data: self,
        }
    }

    fn anchor_unwrap(wrapped: AnchorWrapper<Self>) -> Option<Self> {
        let AnchorWrapper::<Self> {
            discriminator,
            data,
        } = wrapped;
        (discriminator == Self::DISCRIMINATOR).then_some(data)
    }

    fn anchor_unwrap_from_bytes<T: AsRef<[u8]>>(bytes: T) -> Option<Self> {
        let mut bytes = bytes.as_ref();
        AnchorWrapper::<Self>::deserialize(&mut bytes)
            /*
            .or_else(|e| {
                println!("{e:?}");
                Err(e)
            })
            */
            .ok()
            .and_then(Self::anchor_unwrap)
    }
}

trait AnchorAccount: AnchorData {
    const PROGRAM_ID: Pubkey;
    fn query(rpc_client: &RpcClient, address: &Pubkey) -> client_error::Result<Option<Self>> {
        println!("{address}");
        let account = rpc_client.get_account(address)?;
        let maybe_anchor_data = (account.owner == Self::PROGRAM_ID)
            .then_some(account.data)
            .map(|d| {
                println!("{d:02x?}");
                d
            })
            .and_then(Self::anchor_unwrap_from_bytes);
        Ok(maybe_anchor_data)
    }
}

trait SquadsAccount {}

impl<T> AnchorAccount for T
where
    T: SquadsAccount + AnchorData,
{
    const PROGRAM_ID: Pubkey = SQUADS_MPL_PROGRAM_ID;
}

pub fn squads_multisig_pda(create_key: &Pubkey) -> (Pubkey, u8) {
    let seeds = [b"squad", create_key.as_ref(), b"multisig"];
    Pubkey::find_program_address(&seeds, &SQUADS_MPL_PROGRAM_ID)
}

pub fn squads_transaction_pda(multisig_address: &Pubkey, transaction_index: u32) -> (Pubkey, u8) {
    let seeds = [
        b"squad",
        multisig_address.as_ref(),
        &transaction_index.to_le_bytes(),
        b"transaction",
    ];
    Pubkey::find_program_address(&seeds, &SQUADS_MPL_PROGRAM_ID)
}

#[derive(Debug, BorshDeserialize, BorshSerialize)]
struct CreateMultisigInstructionData {
    threshold: u16,
    create_key: Pubkey,
    members: Vec<Pubkey>,
    meta: String,
}

impl AnchorData for CreateMultisigInstructionData {
    const DISCRIMINATOR: [u8; 8] = [0x18, 0x1e, 0xc8, 0x28, 0x05, 0x1c, 0x07, 0x77];
}

impl CreateMultisigInstructionData {
    pub fn new(threshold: u16, create_key: Pubkey, members: Vec<Pubkey>, meta: String) -> Self {
        Self {
            threshold,
            create_key,
            members,
            meta,
        }
    }
}

fn create_multisig_instruction(
    creator: Pubkey,
    threshold: u16,
    create_key: Pubkey,
    members: Vec<Pubkey>,
    meta: String,
) -> Instruction {
    let (multisig_address, _bump) = squads_multisig_pda(&create_key);
    let accounts = vec![
        AccountMeta::new(multisig_address, false),
        AccountMeta::new(creator, true),
        AccountMeta::new_readonly(system_program::id(), false),
    ];
    let data =
        CreateMultisigInstructionData::new(threshold, create_key, members, meta).anchor_wrap();
    Instruction::new_with_borsh(SQUADS_MPL_PROGRAM_ID, &data, accounts)
}

#[derive(Debug, BorshDeserialize, BorshSerialize)]
struct CreateTransactionInstructionData {
    // nfc where anchor gets this from. there's no reference to an
    // `authority_index` in the ix definition
    authority_index: u32,
}

impl AnchorData for CreateTransactionInstructionData {
    const DISCRIMINATOR: [u8; 8] = [0xe3, 0xc1, 0x35, 0xef, 0x37, 0x7e, 0x70, 0x69];
}

impl CreateTransactionInstructionData {
    pub fn new(authority_index: u32) -> Self {
        Self { authority_index }
    }
}

pub fn create_transaction_instruction(
    creator: Pubkey,
    multisig_address: Pubkey,
    authority_index: u32,
    next_transaction_index: u32,
) -> Instruction {
    let (transaction_address, _bump) =
        squads_transaction_pda(&multisig_address, next_transaction_index);
    let accounts = vec![
        AccountMeta::new(multisig_address, false),
        AccountMeta::new(transaction_address, false),
        AccountMeta::new(creator, true),
        AccountMeta::new_readonly(system_program::id(), false),
    ];
    let data = CreateTransactionInstructionData::new(authority_index).anchor_wrap();
    Instruction::new_with_borsh(SQUADS_MPL_PROGRAM_ID, &data, accounts)
}

#[derive(Debug, BorshDeserialize, BorshSerialize)]
struct MultisigAccount {
    pub threshold: u16,
    pub authority_index: u16,
    pub transaction_index: u32,
    pub ms_change_index: u32,
    pub bump: u8,
    pub create_key: Pubkey,
    pub allow_external_execute: bool,
    pub member_keys: Vec<Pubkey>,
}

impl AnchorData for MultisigAccount {
    const DISCRIMINATOR: [u8; 8] = [0x46, 0x76, 0x09, 0x6c, 0xfe, 0xd7, 0x1f, 0x78];
}

impl SquadsAccount for MultisigAccount {}

#[derive(Debug, BorshDeserialize, BorshSerialize)]
struct ActivateTransactionInstructionData {}

impl AnchorData for ActivateTransactionInstructionData {
    const DISCRIMINATOR: [u8; 8] = [0x38, 0x11, 0x00, 0xa3, 0x87, 0x0b, 0x87, 0x20];
}

pub fn activate_transaction_instruction(
    multisig_address: Pubkey,
    creator: Pubkey,
    transaction_index: u32,
) -> Instruction {
    let (transaction_address, _bump) = squads_transaction_pda(&multisig_address, transaction_index);
    let accounts = vec![
        AccountMeta::new_readonly(multisig_address, false),
        AccountMeta::new(transaction_address, false),
        AccountMeta::new(creator, true),
    ];
    let data = ActivateTransactionInstructionData {};
    Instruction::new_with_borsh(SQUADS_MPL_PROGRAM_ID, &data, accounts)
}

#[repr(u16)]
#[derive(Debug, BorshDeserialize, BorshSerialize, PartialEq, Eq)]
enum TransactionStatus {
    Draft,
    Active,
    ExecuteReady,
    Executed,
    Rejected,
    Cancelled,
}

#[derive(Debug, BorshDeserialize, BorshSerialize)]
struct TransactionAccount {
    creator: Pubkey,
    multisig_address: Pubkey,
    transaction_index: u32,
    authority_index: u32,
    authority_bump: u8,
    status: TransactionStatus,
    instruction_index: u8,
    bump: u8,
    approved: Vec<Pubkey>,
    rejected: Vec<Pubkey>,
    cancelled: Vec<Pubkey>,
    executed_index: u8,
}

impl AnchorData for TransactionAccount {
    const DISCRIMINATOR: [u8; 8] = [0xb6, 0x97, 0x68, 0xd8, 0xff, 0x01, 0x13, 0x9d];
}

impl SquadsAccount for TransactionAccount {}

#[derive(Debug, BorshDeserialize, BorshSerialize)]
struct VoteTransactionInstructionData {}

impl AnchorData for VoteTransactionInstructionData {
    const DISCRIMINATOR: [u8; 8] = [0xe0, 0x27, 0x58, 0xb5, 0x24, 0x3b, 0x9b, 0x7a];
}

pub fn vote_transaction_instruction(
    transaction_address: Pubkey,
    multisig_address: Pubkey,
    multisig_member: Pubkey,
) -> Instruction {
    let accounts = vec![
        AccountMeta::new_readonly(multisig_address, false),
        AccountMeta::new(transaction_address, false),
        AccountMeta::new(multisig_member, true),
    ];
    let data = VoteTransactionInstructionData {}.anchor_wrap();
    Instruction::new_with_borsh(SQUADS_MPL_PROGRAM_ID, &data, accounts)
}

fn main() {
    let default_config_file = CONFIG_FILE.as_ref().expect("HOME envvar resolved");
    let arg_matches = clap::App::new("squads-mpl")
        .setting(clap::AppSettings::SubcommandRequiredElseHelp)
        .arg(clap::Arg::with_name("config")
            .long("config")
            .takes_value(true)
            .value_name("PATH")
            .default_value(default_config_file)
            .help("config file to use")
        )
        .arg(
            clap::Arg::with_name("json_rpc_url")
                .short("u")
                .long("url")
                .value_name("URL_OR_MONIKER")
                .takes_value(true)
                .global(true)
                .validator(is_url_or_moniker)
                .help(
                    "URL for Solana's JSON RPC or moniker (or their first letter): \
                       [mainnet-beta, testnet, devnet, localhost]",
                ),
        )
        .arg(clap::Arg::with_name("keypair")
            .short("k")
            .long("keypair")
            .takes_value(true)
            .global(true)
            .value_name("SIGNER")
            .help("default signer")
        )
        .subcommand(clap::SubCommand::with_name("multisig-create")
            .arg(clap::Arg::with_name("threshold")
                .index(1)
                .value_name("THRESHOLD")
                .required(true)
                .validator(|s| {
                    u16::from_str(&s)
                        .map(|_| ())
                        .map_err(|e| e.to_string())
                })
                .help("minimum members required to sign")
            )
            .arg(clap::Arg::with_name("metadata")
                .index(2)
                .value_name("METADATA_JSON_STRING")
                .required(true)
                .help("nfc some json shit?")
            )
            .arg(clap::Arg::with_name("members")
                .index(3)
                .value_name("MULTISIG_MEMBER")
                .required(true)
                .multiple(true)
                .validator(is_valid_pubkey)
                .help("members of the multisig set")
            )
            .arg(clap::Arg::with_name("create_key")
                .long("create-key")
                .value_name("PUBKEY")
                .required(true)
                .validator(is_valid_signer)
                .help("just some bytes to make the pda unique. randomly generated by default")
            )
            .arg(clap::Arg::with_name("creator")
                .long("creator")
                .takes_value(true)
                .value_name("SIGNER")
                .validator(is_valid_signer)
                .help("nfc. just signs for fun apparently")
            )
            .offline_args()
        )
        .subcommand(clap::SubCommand::with_name("transaction-create")
            .arg(clap::Arg::with_name("multisig_address")
                .index(1)
                .value_name("MULTISIG_ADDRESS")
                .validator(is_pubkey)
                .help("address of multisig account to create transaction under")
            )
            .arg(clap::Arg::with_name("creator")
                .long("creator")
                .takes_value(true)
                .value_name("SIGNER")
                .validator(is_valid_signer)
                .help("signer for member creating the transaction")
            )
            .offline_args()
        )
        /*
        .subcommand(clap::SubCommand::with_name("transaction-add-instruction")
            .arg(clap::Arg::with_name("")
            )
        )
        */
        .subcommand(clap::SubCommand::with_name("transaction-vote")
            .arg(clap::Arg::with_name("transaction_address")
                .index(1)
                .value_name("TRANSACTION_ADDRESS")
                .required(true)
                .help("address of tranaction account to vote on")
            )
            .arg(clap::Arg::with_name("multisig_member")
                .long("multisig-member")
                .takes_value(true)
                .value_name("SIGNER")
                .validator(is_valid_signer)
                .help("multisig member voting on the transactions. defaults to `--keypair` or cli config signer")
            )
        )
        .get_matches();

    let config_path = clap::value_t_or_exit!(arg_matches, "config", String);
    let cli_config = Config::load(&config_path).expect("successful config load");
    let (_, json_rpc_url) = ConfigInput::compute_json_rpc_url_setting(
        arg_matches.value_of("json_rpc_url").unwrap_or(""),
        &cli_config.json_rpc_url,
    );
    let commitment = CommitmentConfig::from_str(&cli_config.commitment).unwrap_or_default();
    let keypair_path =
        clap::value_t!(arg_matches, "keypair", String).unwrap_or(cli_config.keypair_path);
    let default_signer = DefaultSigner::new("keypair", keypair_path);

    let rpc_client = RpcClient::new_with_commitment(json_rpc_url, commitment);
    let (fee_payer_key, fee_payer_pubkey) = (None, Option::<Pubkey>::None);
    let mut bulk_signers = vec![fee_payer_key];
    let mut wallet_manager = None;

    let maybe_ix_batch: Option<(Vec<Instruction>, CliSignerInfo)> = match arg_matches.subcommand() {
        ("multisig-create", Some(sub_matches)) => {
            let threshold = value_t_or_exit!(sub_matches, "threshold", u16);
            let metadata = sub_matches
                .value_of("metadata")
                .map(String::from)
                .expect("valid `metadata` string");
            let members = pubkeys_of_multiple_signers(&sub_matches, "members", &mut wallet_manager)
                .expect("valid `members` pubkeys")
                .expect("`members` arg exists");
            let create_key = pubkey_of(&sub_matches, "create_key").unwrap_or_else(|| {
                let create_key = Pubkey::new_rand();
                println!("create-key: {create_key}");
                create_key
            });
            let (creator_key, creator_pubkey) =
                signer_of(&sub_matches, "creator", &mut wallet_manager)
                    .expect("`creator` is valid signer");

            bulk_signers.push(creator_key);
            let signer_info = default_signer
                .generate_unique_signers(bulk_signers, &sub_matches, &mut wallet_manager)
                .expect("unique signers");
            let creator_pubkey =
                signer_info.signers[signer_info.index_of(creator_pubkey).unwrap()].pubkey();

            let ix = create_multisig_instruction(
                creator_pubkey,
                threshold,
                create_key,
                members,
                metadata,
            );
            println!("{ix:?}");

            //Some(vec![ix], bulk_signers)
            None
        }
        ("transaction-create", Some(sub_matches)) => {
            let multisig_address =
                pubkey_of(&sub_matches, "multisig_address").expect("`multisig_address` on cli");
            let (creator_key, creator_pubkey) =
                signer_of(&sub_matches, "creator", &mut wallet_manager)
                    .expect("`creator` is valid signer");

            bulk_signers.push(creator_key);

            let signer_info = default_signer
                .generate_unique_signers(bulk_signers, &sub_matches, &mut wallet_manager)
                .expect("unique signers");
            let creator_pubkey =
                signer_info.signers[signer_info.index_of(creator_pubkey).unwrap()].pubkey();

            let MultisigAccount {
                authority_index,
                transaction_index,
                member_keys,
                ..
            } = MultisigAccount::query(&rpc_client, &multisig_address)
                .unwrap()
                .unwrap();
            assert!(
                member_keys.contains(&creator_pubkey),
                "`creator` MUST be in `multisig.member_keys`"
            );
            let authority_index = u32::from(authority_index);
            let next_transaction_index = transaction_index
                .checked_add(1)
                .expect("have not created 4B transactions");

            let ix = create_transaction_instruction(
                creator_pubkey,
                multisig_address,
                authority_index,
                next_transaction_index,
            );
            println!("{ix:?}");

            //Some((vec![ix], signer_info))
            None
        }
        ("transaction-vote", Some(sub_matches)) => {
            let transaction_address = pubkey_of(&sub_matches, "transaction_address")
                .expect("`transaction_address` on cli");
            let (multisig_member_key, multisig_member_pubkey) =
                signer_of(&sub_matches, "multisig_member", &mut wallet_manager)
                    .expect("valid `multisig_member`");

            bulk_signers.push(multisig_member_key);
            let signer_info = default_signer
                .generate_unique_signers(bulk_signers, &sub_matches, &mut wallet_manager)
                .expect("unique signers");
            let multisig_member_pubkey =
                signer_info.signers[signer_info.index_of(multisig_member_pubkey).unwrap()].pubkey();

            println!("tx: {transaction_address}, voter: {multisig_member_pubkey}");

            let TransactionAccount {
                creator,
                multisig_address,
                transaction_index,
                status,
                ..
            } = TransactionAccount::query(&rpc_client, &transaction_address)
                .unwrap()
                .unwrap();
            assert_eq!(
                status,
                TransactionStatus::Active,
                "`transaction.status MUST be `Active`"
            );

            let MultisigAccount {
                ms_change_index,
                create_key,
                member_keys,
                ..
            } = MultisigAccount::query(&rpc_client, &multisig_address)
                .unwrap()
                .unwrap();
            assert!(
                transaction_index > ms_change_index,
                "`multsig` account MUST NOT have changed since `transaction` creation"
            );
            assert!(
                member_keys.contains(&creator),
                "`transaction.creator` MUST be in `multisig.member_keys`"
            );

            assert!(
                member_keys.contains(&multisig_member_pubkey),
                "voting `multisig_member_pubkey` MUST be in `multisig.member_keys`"
            );

            let ix = vote_transaction_instruction(
                transaction_address,
                multisig_address,
                multisig_member_pubkey,
            );
            println!("{ix:?}");
            Some((vec![ix], signer_info))
        }
        _ => unreachable!(),
    };
    if let Some((ix_batch, signer_info)) = maybe_ix_batch {
        let fee_payer_pubkey = signer_info.signers[signer_info
            .index_of(fee_payer_pubkey)
            .expect("fee_payer_pubkey index")]
        .pubkey();
        let message = Message::new(&ix_batch, Some(&fee_payer_pubkey));

        let recent_blockhash = rpc_client.get_latest_blockhash().expect("recent blockhash");
        let signers = signer_info.signers_for_message(&message);
        let transaction = Transaction::new(&signers, message, recent_blockhash);
        let tx_id = rpc_client
            .send_and_confirm_transaction_with_spinner(&transaction)
            .expect("tx broadcast success");
        println!("tx: {tx_id}");
    }
}

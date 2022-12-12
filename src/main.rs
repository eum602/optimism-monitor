use anyhow::anyhow;
use anyhow::Ok;
use hex_literal::hex;
use log::info;
use sha3::Digest;
use sha3::Keccak256;
use std::fs::File;
use std::result::Result::Ok as ROk;
use std::time::Duration;
use web3::api::BaseFilter;
use web3::futures;
use web3::futures::StreamExt;
use web3::transports::Http;
use web3::types::{Filter, Log};
use web3::{
    contract::{Contract, Options},
    ethabi::{Bytes, Event, Hash, RawLog},
    types::{BlockNumber, FilterBuilder, U64},
};
mod utils;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = env_logger::try_init();
    let optimism_contract = get_optimism_contract_interface().await?;
    let _p = start_routine_on_mainnet(&optimism_contract).await?;
    Ok(())
}

async fn get_ethereum_contract_interface(
    from: i32,
    to: i32,
    url: &str,
) -> anyhow::Result<BaseFilter<Http, Log>> {
    let http = web3::transports::Http::new(url)?;
    //let eth = Eth::new(http);
    let web3 = web3::Web3::new(http);
    let contract_address = hex!("25ace71c97B33Cc4729CF772ae268934F7ab5fA1").into();
    // Accessing existing contract
    let contract = Contract::from_json(
        web3.eth(),
        contract_address,
        include_bytes!("./contracts/abi/ICrossDomainMessenger.abi"),
    )?;

    let filter: Filter;

    if from == 0 && to == 0 {
        filter = FilterBuilder::default()
            .address(vec![contract.address()])
            .topics(
                Some(vec![hex!(
                    "4641df4a962071e12719d8c8c8e5ac7fc4d97b927346a3d7a335b1f7517e133c"
                )
                .into()]),
                None,
                None,
                None,
            )
            .build();
    } else {
        filter = FilterBuilder::default()
            .address(vec![contract.address()])
            .topics(
                Some(vec![hex!(
                    "4641df4a962071e12719d8c8c8e5ac7fc4d97b927346a3d7a335b1f7517e133c"
                )
                .into()]),
                None,
                None,
                None,
            )
            .from_block(BlockNumber::Number(U64::from(from)))
            .to_block(BlockNumber::Number(U64::from(to)))
            .build();
    }

    let filter = web3.eth_filter().create_logs_filter(filter).await?;
    Ok(filter)
}

async fn start_routine_on_mainnet(optimism_contract: &Contract<Http>) -> anyhow::Result<()> {
    info!("\nEthereum: L1CrossDomainMessenger 0x25ace71c97B33Cc4729CF772ae268934F7ab5fA1");
    info!("Checking on ethereum block 16162765 (just to verify flow is working)");
    let from = 16162765;
    let to = 16162765;
    let r = match utils::Utils::get_env_or_err("ethereum_rpc_url") {
        ROk(value) => anyhow::Ok(value),
        Err(_) => panic!("Please set ethereum_rpc_url environment variable"),
    };
    let url = &r.unwrap();
    let f = get_ethereum_contract_interface(from, to, url)
        .await
        .unwrap();

    let event = load_event(
        "./src/contracts/abi/ICrossDomainMessenger.abi",
        "RelayedMessage",
    )
    .unwrap();

    let _r1 = print_results_for_block(optimism_contract, event.clone(), f).await;

    info!("\nStarting Real Time Listening ... as soon as a new message comming from optimism is relayed to ethereum mainnet, that will be tracked here");
    let f = get_ethereum_contract_interface(0, 0, url).await.unwrap();
    let logs_stream = f.stream(Duration::from_secs(1));

    futures::pin_mut!(logs_stream);
    let log = logs_stream.next().await.unwrap().unwrap();
    let message_hash = extract_relayed_message_from_log(event, log).await.unwrap();
    let _r = verify_on_optimism(optimism_contract, message_hash);

    Ok(())
}

async fn print_results_for_block(
    optimism_contract: &Contract<Http>,
    event: Event,
    filter: BaseFilter<Http, Log>,
) -> anyhow::Result<()> {
    let logs = filter.logs().await.unwrap();
    for log in logs {
        let relayed_message = extract_relayed_message_from_log(event.clone(), log)
            .await
            .unwrap();
        let _r = verify_on_optimism(&optimism_contract, relayed_message).await;
    }

    Ok(())
}

async fn extract_relayed_message_from_log(event: Event, log: Log) -> anyhow::Result<String> {
    let mut topics: Vec<Hash> = vec![];
    for t in log.topics {
        topics.push(Hash::from_slice(t.as_bytes()));
    }

    let raw_log = RawLog {
        topics,
        data: Bytes::from(log.data.0),
    };
    let decoded = event.parse_log(raw_log)?;
    let relayed_message = decoded.params[0].value.to_string();
    Ok(relayed_message)
}

async fn verify_on_optimism(
    optimism_contract: &Contract<Http>,
    message_hash: String,
) -> anyhow::Result<()> {
    let m = hex::decode(message_hash.clone()).expect("Failed!");
    let mut as_bytes: [u8; 32] = [0; 32];
    as_bytes.copy_from_slice(&m);

    let result =
        optimism_contract.query("sentMessages", (as_bytes,), None, Options::default(), None);
    let is_registered: bool = result.await.unwrap();
    info!(
        "Ethereum Message Hash: {}; Is registered on Optimism Network? {}",
        message_hash, is_registered
    );
    Ok(())
}

async fn get_optimism_contract_interface() -> anyhow::Result<Contract<Http>> {
    let http = web3::transports::Http::new("https://mainnet.optimism.io")?;
    //let eth = Eth::new(http);
    let web3 = web3::Web3::new(http);
    let contract_address = hex!("4200000000000000000000000000000000000007").into();
    // Accessing existing contract
    let contract = Contract::from_json(
        web3.eth(),
        contract_address,
        include_bytes!("../src/contracts/abi/L2CrossDomainMessenger_short.abi"),
    )?;

    info!(
        "\nOptimism: L2CrossDomainMessenger Contract: {:?}",
        contract.address()
    );
    Ok(contract)
}

fn load_event(path: &str, name_or_signature: &str) -> anyhow::Result<Event> {
    let file = File::open(path)?;
    let contract = web3::ethabi::Contract::load(file)?;

    let params_start = name_or_signature.find('(');
    match params_start {
        Some(params_start) => {
            let name = &name_or_signature[..params_start];
            let signature = Hash::from_slice(
                Keccak256::digest(name_or_signature.replace(' ', "").as_bytes()).as_slice(),
            );
            contract
                .events_by_name(name)?
                .iter()
                .find(|event| event.signature() == signature)
                .cloned()
                .ok_or_else(|| anyhow!("Invalid Signature `{}`", signature))
        }
        None => {
            let events = contract.events_by_name(name_or_signature)?;
            match events.len() {
                0 => unreachable!(),
                1 => Ok(events[0].clone()),
                _ => Err(anyhow!(
                    "More than one function found for name `{}`, try providing full signature",
                    name_or_signature
                )),
            }
        }
    }
}

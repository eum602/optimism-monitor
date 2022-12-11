use hex_literal::hex;
use web3::contract::{Contract, Options};

#[tokio::main]
async fn main() -> web3::contract::Result<()> {
    let _ = env_logger::try_init();
    let _r = verify_on_optimism().await;
    Ok(())
}

async fn verify_on_optimism() -> web3::contract::Result<()> {
    let http = web3::transports::Http::new("https://mainnet.optimism.io")?;
    //let eth = Eth::new(http);
    let web3 = web3::Web3::new(http);
    let contract_address = hex!("4200000000000000000000000000000000000000").into();
    // Accessing existing contract
    let contract = Contract::from_json(
        web3.eth(),
        contract_address,
        include_bytes!("../src/contracts/abi/iOVM_L2ToL1MessagePasser.abi"),
    )?;

    println!("CA: {}", contract.address());

    let hex_to_query = hex!("234440");

    let result = contract.query(
        "sentMessages",
        (hex_to_query,),
        None,
        Options::default(),
        None,
    );
    // Make sure to specify the expected return type, to prevent ambiguous compiler
    // errors about `Detokenize` missing for `()`.
    let is_registered: bool = result.await?;
    println!("Is registered? {}", is_registered);
    Ok(())
}

# RpoFalcon512Conditional Usage Example

The `RpoFalcon512Conditional` component provides conditional authentication for Miden accounts. It only requires signature verification when specific tracked procedures are called during a transaction.

## Use Case: Fungible Faucet with Conditional Authentication

The primary use case (as outlined in issue #1489) is for fungible faucets where:
- The `burn` procedure can be called by anyone without authentication
- The `distribute` procedure requires authentication

## Example Implementation

```rust
use miden_lib::account::{
    auth::RpoFalcon512Conditional,
    faucets::BasicFungibleFaucet,
};
use miden_objects::{
    Digest,
    account::{AccountBuilder, AccountType},
    crypto::dsa::rpo_falcon512::PublicKey,
};

// Create a faucet with conditional authentication
fn create_conditional_faucet() {
    // Generate or load your public key
    let public_key = PublicKey::new([/* your key data */]);
    
    // Get the MAST root of the distribute procedure
    // In practice, you would get this from the compiled faucet library
    // Example: If you have the faucet component already:
    // let faucet_lib = basic_fungible_faucet_library();
    // let distribute_proc_root = faucet_lib
    //     .mast_forest()
    //     .procedure_digests()
    //     .find(|digest| /* match against known distribute procedure */)
    //     .expect("distribute procedure should exist");
    let distribute_proc_root = Digest::new([/* distribute procedure root */]);
    
    // Create the conditional auth component that only requires 
    // authentication for the distribute procedure
    let conditional_auth = RpoFalcon512Conditional::new(
        public_key,
        vec![distribute_proc_root], // Only track distribute
    );
    
    // Create the faucet component
    let faucet = BasicFungibleFaucet::new(
        symbol,      // e.g., "USDC"
        decimals,    // e.g., 6
        max_supply,  // e.g., 1_000_000_000
    ).unwrap();
    
    // Build the account with both components
    let (account, seed) = AccountBuilder::new(init_seed)
        .account_type(AccountType::FungibleFaucet)
        .with_component(conditional_auth)
        .with_component(faucet)
        .build()
        .unwrap();
}
```

## Storage Layout

The `RpoFalcon512Conditional` component uses the following storage layout:

| Slot | Content | Description |
|------|---------|-------------|
| 0 | Public Key | The RpoFalcon512 public key for signature verification |
| 1 | Count | Number of tracked procedures (as u32 in first felt) |
| 2+ | Procedure Roots | One slot per tracked procedure root |

## Authentication Flow

When a transaction is executed:

1. The `auth__tx_rpo_falcon512_conditional` procedure is called
2. It loops through all tracked procedures (stored in slots 2+)
3. For each tracked procedure, it checks if it was called during the transaction
4. If any tracked procedure was called, standard RpoFalcon512 signature verification is performed
5. If no tracked procedures were called, authentication is skipped

## Current Limitations

**Important**: The transaction introspection functionality (`was_procedure_called`) is not yet implemented (see issue #1489). The current implementation includes a placeholder that always returns `false`, effectively disabling authentication. Once the introspection feature is implemented, the MASM code will need to be updated to use the actual `account::was_procedure_called` procedure.

## Benefits

1. **Flexibility**: Different procedures can have different authentication requirements
2. **Efficiency**: No signature verification overhead for procedures that don't need it
3. **Security**: Critical procedures remain protected while allowing public access to others
4. **Composability**: Can be combined with any other account components

## Future Enhancements

Once transaction introspection is fully implemented, this component could be extended to:
- Support different authentication methods for different procedures
- Track the number of times each procedure was called
- Implement time-based or threshold-based authentication requirements
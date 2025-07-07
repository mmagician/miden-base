use miden_lib::{
    account::{AccountBuilder, auth::RpoFalcon512ProcedureACL, wallets::BasicWallet},
    transaction::TransactionKernel,
};
use miden_objects::{
    account::{Account, AccountCode, AccountComponent, AccountId, AccountStorageMode, AccountType},
    assembly::Assembler,
    assets::FungibleAsset,
    crypto::dsa::rpo_falcon512::SecretKey,
    note::NoteType,
    testing::account_component::AccountMockComponent,
    transaction::{ExecutedTransaction, TransactionArgs},
    Digest, Felt,
};
use miden_testing::{Auth, MockChain, TransactionContextBuilder, TxContextInput};
use miden_tx::TransactionExecutor;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[test]
fn test_rpo_falcon_procedure_acl_with_two_procedures() -> anyhow::Result<()> {
    // Create a mock component with two procedures that we'll use as trigger procedures
    let assembler = TransactionKernel::assembler();
    let mock_component = AccountMockComponent::new_with_slots(
        assembler.clone(),
        vec![
            // First procedure - a simple test procedure
            r#"
            export.test_procedure_1
                push.42
                drop
            end
            "#,
            // Second procedure - another test procedure 
            r#"
            export.test_procedure_2
                push.84
                drop
            end
            "#,
        ],
    )?;

    // Get the MAST roots of the two procedures to use as trigger procedures
    let procedures = mock_component.procedures();
    assert!(procedures.len() >= 2, "Mock component should have at least 2 procedures");
    
    let trigger_proc_1 = procedures[0].0;
    let trigger_proc_2 = procedures[1].0;
    let trigger_procedures = vec![trigger_proc_1, trigger_proc_2];
    
    // Create a secret key and public key for authentication
    let mut rng = ChaCha20Rng::from_seed(Default::default());
    let sec_key = SecretKey::with_rng(&mut rng);
    let pub_key = sec_key.public_key();
    
    // Create the RpoFalcon512ProcedureACL authentication component
    let auth_component = RpoFalcon512ProcedureACL::new(pub_key, trigger_procedures.clone());
    
    // Build an account with the ACL authentication and mock component
    let account = AccountBuilder::new()
        .with_component(auth_component.into())
        .with_component(mock_component.into())
        .with_component(BasicWallet.into())
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Private)
        .build()?;
    
    // Create a MockChain and add the account
    let mut mock_chain = MockChain::new();
    mock_chain.add_pending_account(account.clone());
    mock_chain.prove_next_block()?;
    
    // Create a note to consume
    let note = mock_chain.add_pending_p2id_note(
        AccountId::try_from(0x1234567890abcdef_u64)?,
        account.id(),
        &[FungibleAsset::mock(100)],
        NoteType::Public,
    )?;
    mock_chain.prove_next_block()?;
    
    // Test 1: Execute transaction calling one of the trigger procedures (should require authentication)
    let tx_script_with_trigger = format!(
        r#"
        begin
            push.{} push.{} push.{} push.{}
            call.{:#x}
        end
        "#,
        trigger_proc_1.as_elements()[3],
        trigger_proc_1.as_elements()[2],
        trigger_proc_1.as_elements()[1],
        trigger_proc_1.as_elements()[0],
        account.id().suffix(),
    );
    
    // Create the authenticator using the ProcedureAcl variant
    let auth = Auth::ProcedureAcl { trigger_procedures: trigger_procedures.clone() };
    let (_, authenticator) = auth.build_component();
    
    // Build transaction context with the authenticator
    let tx_context = TransactionContextBuilder::new(account.clone())
        .authenticator(authenticator.unwrap())
        .input_notes(vec![note.clone()])
        .tx_script_code(&tx_script_with_trigger, assembler.clone())?
        .build();
        
    // Execute the transaction - this should succeed because we provided the authenticator
    let executed_tx = tx_context.execute()?;
    assert_eq!(executed_tx.initial_account().id(), account.id());
    
    // Test 2: Execute transaction without calling trigger procedures (should not require authentication)
    let tx_script_without_trigger = r#"
        begin
            push.123
            drop
        end
    "#;
    
    // Build transaction context without calling trigger procedures
    let tx_context_no_trigger = TransactionContextBuilder::new(account.clone())
        .authenticator(authenticator.unwrap())
        .tx_script_code(tx_script_without_trigger, assembler.clone())?
        .build();
        
    // This should also succeed, but authentication won't be triggered
    let executed_tx_no_trigger = tx_context_no_trigger.execute()?;
    assert_eq!(executed_tx_no_trigger.initial_account().id(), account.id());
    
    Ok(())
}

#[test]
fn test_rpo_falcon_procedure_acl_multiple_trigger_procedures() -> anyhow::Result<()> {
    // Create a mock component with multiple procedures
    let assembler = TransactionKernel::assembler();
    let mock_component = AccountMockComponent::new_with_slots(
        assembler.clone(),
        vec![
            r#"
            export.proc_a
                push.1 drop
            end
            "#,
            r#"
            export.proc_b  
                push.2 drop
            end
            "#,
            r#"
            export.proc_c
                push.3 drop
            end
            "#,
        ],
    )?;

    // Get procedure MAST roots - use first two as trigger procedures
    let procedures = mock_component.procedures();
    let trigger_procedures = vec![procedures[0].0, procedures[1].0];
    let non_trigger_proc = procedures[2].0;
    
    // Create authentication component
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let sec_key = SecretKey::with_rng(&mut rng);
    let pub_key = sec_key.public_key();
    let auth_component = RpoFalcon512ProcedureACL::new(pub_key, trigger_procedures.clone());
    
    // Build account
    let account = AccountBuilder::new()
        .with_component(auth_component.into())
        .with_component(mock_component.into())
        .with_component(BasicWallet.into())
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Private)
        .build()?;
    
    // Create authenticator
    let auth = Auth::ProcedureAcl { trigger_procedures };
    let (_, authenticator) = auth.build_component();
    
    // Test calling non-trigger procedure (should not require authentication)
    let tx_script_non_trigger = format!(
        r#"
        begin
            push.{} push.{} push.{} push.{}
            call.{:#x}
        end
        "#,
        non_trigger_proc.as_elements()[3],
        non_trigger_proc.as_elements()[2],
        non_trigger_proc.as_elements()[1],
        non_trigger_proc.as_elements()[0],
        account.id().suffix(),
    );
    
    let tx_context = TransactionContextBuilder::new(account.clone())
        .authenticator(authenticator.unwrap())
        .tx_script_code(&tx_script_non_trigger, assembler)?
        .build();
        
    // This should succeed without triggering authentication
    let executed_tx = tx_context.execute()?;
    assert_eq!(executed_tx.initial_account().id(), account.id());
    
    Ok(())
}
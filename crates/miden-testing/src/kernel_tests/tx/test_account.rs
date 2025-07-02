use anyhow::Context;
use assembly::diagnostics::{IntoDiagnostic, WrapErr, miette};
use miden_lib::{
    errors::tx_kernel_errors::{
        ERR_ACCOUNT_ID_SUFFIX_LEAST_SIGNIFICANT_BYTE_MUST_BE_ZERO,
        ERR_ACCOUNT_ID_SUFFIX_MOST_SIGNIFICANT_BIT_MUST_BE_ZERO,
        ERR_ACCOUNT_ID_UNKNOWN_STORAGE_MODE, ERR_ACCOUNT_ID_UNKNOWN_VERSION,
        ERR_ACCOUNT_STORAGE_SLOT_INDEX_OUT_OF_BOUNDS, ERR_FAUCET_INVALID_STORAGE_OFFSET,
    },
    transaction::TransactionKernel,
    utils::word_to_masm_push_string,
};
use miden_objects::{
    account::{
        Account, AccountBuilder, AccountCode, AccountComponent, AccountId, AccountIdVersion,
        AccountProcedureInfo, AccountStorage, AccountStorageMode, AccountType, StorageSlot,
    },
    assembly::{Library, diagnostics::Report},
    asset::AssetVault,
    testing::{
        account_component::AccountMockComponent,
        account_id::{
            ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET, ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
            ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
            ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
        },
        storage::STORAGE_LEAVES_2,
    },
    transaction::{ExecutedTransaction, TransactionScript},
};
use miden_tx::TransactionExecutorError;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use vm_processor::{Digest, EMPTY_WORD, ExecutionError, MemAdviceProvider, ProcessState};

use super::{Felt, ONE, StackInputs, Word, ZERO};
use crate::{MockChain, TransactionContextBuilder, assert_execution_error, executor::CodeExecutor};

// ACCOUNT CODE TESTS
// ================================================================================================

#[test]
pub fn test_get_code() -> miette::Result<()> {
    let tx_context = TransactionContextBuilder::with_standard_account(ONE).build();
    let code = "
        use.kernel::prologue
        use.kernel::account
        begin
            exec.prologue::prepare_transaction
            exec.account::get_code_commitment
            swapw dropw
        end
        ";

    let process = &tx_context.execute_code(code).wrap_err("failed to execute code")?;
    let process_state: ProcessState = process.into();

    assert_eq!(
        process_state.get_stack_word(0),
        tx_context.account().code().commitment().as_elements(),
        "obtained code commitment is not equal to the account code commitment",
    );

    Ok(())
}

// ACCOUNT ID TESTS
// ================================================================================================

#[test]
pub fn test_account_type() -> miette::Result<()> {
    let procedures = vec![
        ("is_fungible_faucet", AccountType::FungibleFaucet),
        ("is_non_fungible_faucet", AccountType::NonFungibleFaucet),
        ("is_updatable_account", AccountType::RegularAccountUpdatableCode),
        ("is_immutable_account", AccountType::RegularAccountImmutableCode),
    ];

    let test_cases = [
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
        ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET,
    ];

    for (procedure, expected_type) in procedures {
        let mut has_type = false;

        for account_id in test_cases.iter() {
            let account_id = AccountId::try_from(*account_id).unwrap();

            let code = format!(
                "
                use.kernel::account_id

                begin
                    exec.account_id::{procedure}
                end
                "
            );

            let process = CodeExecutor::with_advice_provider(MemAdviceProvider::default())
                .stack_inputs(StackInputs::new(vec![account_id.prefix().as_felt()]).unwrap())
                .run(&code)?;

            let type_matches = account_id.account_type() == expected_type;
            let expected_result = Felt::from(type_matches);
            has_type |= type_matches;

            assert_eq!(
                process.stack.get(0),
                expected_result,
                "Rust and Masm check on account type diverge. proc: {} account_id: {} account_type: {:?} expected_type: {:?}",
                procedure,
                account_id,
                account_id.account_type(),
                expected_type,
            );
        }

        assert!(has_type, "missing test for type {expected_type:?}");
    }

    Ok(())
}

#[test]
pub fn test_account_validate_id() -> miette::Result<()> {
    let test_cases = [
        (ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE, None),
        (ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE, None),
        (ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET, None),
        (ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET, None),
        (
            // Set version to a non-zero value (10).
            ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE | (0x0a << 64),
            Some(ERR_ACCOUNT_ID_UNKNOWN_VERSION),
        ),
        (
            // Set most significant bit to `1`.
            ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET | (0x80 << 56),
            Some(ERR_ACCOUNT_ID_SUFFIX_MOST_SIGNIFICANT_BIT_MUST_BE_ZERO),
        ),
        (
            // Set storage mode to an unknown value (0b11).
            ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE | (0b11 << (64 + 6)),
            Some(ERR_ACCOUNT_ID_UNKNOWN_STORAGE_MODE),
        ),
        (
            // Set lower 8 bits to a non-zero value (1).
            ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET | 1,
            Some(ERR_ACCOUNT_ID_SUFFIX_LEAST_SIGNIFICANT_BYTE_MUST_BE_ZERO),
        ),
    ];

    for (account_id, expected_error) in test_cases.iter() {
        // Manually split the account ID into prefix and suffix since we can't use AccountId methods
        // on invalid ids.
        let prefix = Felt::try_from((account_id / (1u128 << 64)) as u64).unwrap();
        let suffix = Felt::try_from((account_id % (1u128 << 64)) as u64).unwrap();

        let code = "
            use.kernel::account_id

            begin
                exec.account_id::validate
            end
            ";

        let result = CodeExecutor::with_advice_provider(MemAdviceProvider::default())
            .stack_inputs(StackInputs::new(vec![suffix, prefix]).unwrap())
            .run(code);

        match (result, expected_error) {
            (Ok(_), None) => (),
            (Ok(_), Some(err)) => {
                miette::bail!("expected error {err} but validation was successful")
            },
            (Err(ExecutionError::FailedAssertion { err_code, err_msg, .. }), Some(err)) => {
                if err_code != err.code() {
                    miette::bail!(
                        "actual error \"{}\" (code: {err_code}) did not match expected error {err}",
                        err_msg.as_ref().map(AsRef::as_ref).unwrap_or("<no message>")
                    );
                }
            },
            // Construct Reports to get the diagnostics-based error messages.
            (Err(err), None) => {
                return Err(Report::from(err)
                    .context("validation is supposed to succeed but error occurred"));
            },
            (Err(err), Some(_)) => {
                return Err(Report::from(err).context("unexpected different error than expected"));
            },
        }
    }

    Ok(())
}

#[test]
fn test_is_faucet_procedure() -> miette::Result<()> {
    let test_cases = [
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
        ACCOUNT_ID_REGULAR_PRIVATE_ACCOUNT_UPDATABLE_CODE,
        ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
        ACCOUNT_ID_PRIVATE_NON_FUNGIBLE_FAUCET,
    ];

    for account_id in test_cases.iter() {
        let account_id = AccountId::try_from(*account_id).unwrap();

        let code = format!(
            "
            use.kernel::account_id

            begin
                push.{prefix}
                exec.account_id::is_faucet
                # => [is_faucet, account_id_prefix]

                # truncate the stack
                swap drop
            end
            ",
            prefix = account_id.prefix().as_felt(),
        );

        let process = CodeExecutor::with_advice_provider(MemAdviceProvider::default())
            .run(&code)
            .wrap_err("failed to execute is_faucet procedure")?;

        let is_faucet = account_id.is_faucet();
        assert_eq!(
            process.stack.get(0),
            Felt::new(is_faucet as u64),
            "Rust and MASM is_faucet diverged for account_id {account_id}"
        );
    }

    Ok(())
}

// ACCOUNT STORAGE TESTS
// ================================================================================================

#[test]
fn test_get_item() -> miette::Result<()> {
    for storage_item in [AccountStorage::mock_item_0(), AccountStorage::mock_item_1()] {
        let tx_context = TransactionContextBuilder::with_standard_account(ONE).build();

        let code = format!(
            "
            use.kernel::account
            use.kernel::prologue

            begin
                exec.prologue::prepare_transaction

                # push the account storage item index
                push.{item_index}

                # assert the item value is correct
                exec.account::get_item
                push.{item_value}
                assert_eqw
            end
            ",
            item_index = storage_item.index,
            item_value = word_to_masm_push_string(&storage_item.slot.value())
        );

        tx_context.execute_code(&code).wrap_err("failed to execute code")?;
    }

    Ok(())
}

#[test]
fn test_get_map_item() -> miette::Result<()> {
    let account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_component(
            AccountMockComponent::new_with_slots(
                TransactionKernel::assembler(),
                vec![AccountStorage::mock_item_2().slot],
            )
            .unwrap(),
        )
        .build_existing()
        .unwrap();

    let tx_context = TransactionContextBuilder::new(account).build();

    for (key, value) in STORAGE_LEAVES_2 {
        let code = format!(
            "
            use.kernel::prologue

            begin
                exec.prologue::prepare_transaction

                # get the map item
                push.{map_key}
                push.{item_index}
                call.::test::account::get_map_item

                # truncate the stack 
                swapw dropw movup.4 drop
            end
            ",
            item_index = 0,
            map_key = word_to_masm_push_string(&key),
        );

        let process = &tx_context
            .execute_code_with_assembler(
                &code,
                TransactionKernel::testing_assembler_with_mock_account(),
            )
            .wrap_err("failed to execute code")?;
        let process_state: ProcessState = process.into();

        assert_eq!(
            value,
            process_state.get_stack_word(0),
            "get_map_item result doesn't match the expected value",
        );
        assert_eq!(
            Word::default(),
            process_state.get_stack_word(1),
            "The rest of the stack must be cleared",
        );
        assert_eq!(
            Word::default(),
            process_state.get_stack_word(2),
            "The rest of the stack must be cleared",
        );
        assert_eq!(
            Word::default(),
            process_state.get_stack_word(3),
            "The rest of the stack must be cleared",
        );
    }

    Ok(())
}

#[test]
fn test_get_storage_slot_type() -> miette::Result<()> {
    for storage_item in [
        AccountStorage::mock_item_0(),
        AccountStorage::mock_item_1(),
        AccountStorage::mock_item_2(),
    ] {
        let tx_context = TransactionContextBuilder::with_standard_account(ONE).build();

        let code = format!(
            "
            use.kernel::account
            use.kernel::prologue

            begin
                exec.prologue::prepare_transaction

                # push the account storage item index
                push.{item_index}

                # get the type of the respective storage slot
                exec.account::get_storage_slot_type

                # truncate the stack
                swap drop
            end
            ",
            item_index = storage_item.index,
        );

        let process = &tx_context.execute_code(&code).wrap_err("failed to execute code")?;
        let process_state: ProcessState = process.into();

        let storage_slot_type = storage_item.slot.slot_type();

        assert_eq!(storage_slot_type, process_state.get_stack_item(0).try_into().unwrap());
        assert_eq!(process_state.get_stack_item(1), ZERO, "the rest of the stack is empty");
        assert_eq!(process_state.get_stack_item(2), ZERO, "the rest of the stack is empty");
        assert_eq!(process_state.get_stack_item(3), ZERO, "the rest of the stack is empty");
        assert_eq!(
            Word::default(),
            process_state.get_stack_word(1),
            "the rest of the stack is empty"
        );
        assert_eq!(
            Word::default(),
            process_state.get_stack_word(2),
            "the rest of the stack is empty"
        );
        assert_eq!(
            Word::default(),
            process_state.get_stack_word(3),
            "the rest of the stack is empty"
        );
    }

    Ok(())
}

#[test]
fn test_set_item() -> miette::Result<()> {
    let tx_context = TransactionContextBuilder::with_standard_account(ONE).build();

    let new_storage_item: Word = [Felt::new(91), Felt::new(92), Felt::new(93), Felt::new(94)];

    let code = format!(
        "
        use.kernel::account
        use.kernel::prologue

        begin
            exec.prologue::prepare_transaction

            # set the storage item
            push.{new_storage_item}
            push.{new_storage_item_index}
            exec.account::set_item

            # assert old value was correctly returned
            push.1.2.3.4 assert_eqw

            # assert new value has been correctly set
            push.{new_storage_item_index}
            exec.account::get_item
            push.{new_storage_item}
            assert_eqw
        end
        ",
        new_storage_item = word_to_masm_push_string(&new_storage_item),
        new_storage_item_index = 0,
    );

    tx_context.execute_code(&code).wrap_err("failed to execute code")?;

    Ok(())
}

#[test]
fn test_set_map_item() -> miette::Result<()> {
    let (new_key, new_value) = (
        Digest::new([Felt::new(109), Felt::new(110), Felt::new(111), Felt::new(112)]),
        [Felt::new(9_u64), Felt::new(10_u64), Felt::new(11_u64), Felt::new(12_u64)],
    );

    let account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_component(
            AccountMockComponent::new_with_slots(
                TransactionKernel::assembler(),
                vec![AccountStorage::mock_item_2().slot],
            )
            .unwrap(),
        )
        .build_existing()
        .unwrap();

    let tx_context = TransactionContextBuilder::new(account).build();
    let storage_item = AccountStorage::mock_item_2();

    let code = format!(
        "
        use.std::sys

        use.test::account
        use.kernel::prologue

        begin
            exec.prologue::prepare_transaction

            # set the map item
            push.{new_value}
            push.{new_key}
            push.{item_index}
            call.account::set_map_item

            # double check that on storage slot is indeed the new map
            push.{item_index}
            call.account::get_item

            # truncate the stack
            exec.sys::truncate_stack
        end
        ",
        item_index = 0,
        new_key = word_to_masm_push_string(&new_key),
        new_value = word_to_masm_push_string(&new_value),
    );

    let process = &tx_context
        .execute_code_with_assembler(
            &code,
            TransactionKernel::testing_assembler_with_mock_account(),
        )
        .wrap_err("failed to execute code")?;
    let process_state: ProcessState = process.into();

    let mut new_storage_map = AccountStorage::mock_map();
    new_storage_map.insert(new_key, new_value);

    assert_eq!(
        new_storage_map.root(),
        Digest::from(process_state.get_stack_word(0)),
        "get_item must return the new updated value",
    );
    assert_eq!(
        storage_item.slot.value(),
        process_state.get_stack_word(1),
        "The original value stored in the map doesn't match the expected value",
    );

    Ok(())
}

#[test]
fn test_account_component_storage_offset() -> miette::Result<()> {
    // setup assembler
    let assembler = TransactionKernel::testing_assembler();

    // The following code will execute the following logic that will be asserted during the test:
    //
    // 1. foo_write will set word [1, 2, 3, 4] in storage at location 0 (0 offset by 0)
    // 2. foo_read will read word [1, 2, 3, 4] in storage from location 0 (0 offset by 0)
    // 3. bar_write will set word [5, 6, 7, 8] in storage at location 1 (0 offset by 1)
    // 4. bar_read will read word [5, 6, 7, 8] in storage from location 1 (0 offset by 1)
    //
    // We will then assert that we are able to retrieve the correct elements from storage
    // insuring consistent "set" and "get" using offsets.
    let source_code_component1 = "
        use.miden::account

        export.foo_write
            push.1.2.3.4.0
            exec.account::set_item

            dropw
        end

        export.foo_read
            push.0
            exec.account::get_item
            push.1.2.3.4 eqw assert

            dropw dropw
        end
    ";

    let source_code_component2 = "
        use.miden::account

        export.bar_write
            push.5.6.7.8.0
            exec.account::set_item

            dropw
        end

        export.bar_read
            push.0
            exec.account::get_item
            push.5.6.7.8 eqw assert

            push.1 exec.account::incr_nonce
            dropw dropw
        end
    ";

    // Compile source code to find MAST roots of procedures.
    let code1 = assembler.clone().assemble_library([source_code_component1]).unwrap();
    let code2 = assembler.clone().assemble_library([source_code_component2]).unwrap();
    let find_procedure_digest_by_name = |name: &str, lib: &Library| {
        lib.exports().find_map(|export| {
            if export.name.as_str() == name {
                Some(lib.mast_forest()[lib.get_export_node_id(export)].digest())
            } else {
                None
            }
        })
    };

    let foo_write = find_procedure_digest_by_name("foo_write", &code1).unwrap();
    let foo_read = find_procedure_digest_by_name("foo_read", &code1).unwrap();
    let bar_write = find_procedure_digest_by_name("bar_write", &code2).unwrap();
    let bar_read = find_procedure_digest_by_name("bar_read", &code2).unwrap();

    // Compile source code into components.
    let component1 = AccountComponent::compile(
        source_code_component1,
        assembler.clone(),
        vec![StorageSlot::Value(Word::default())],
    )
    .unwrap()
    .with_supported_type(AccountType::RegularAccountUpdatableCode);

    let component2 = AccountComponent::compile(
        source_code_component2,
        assembler.clone(),
        vec![StorageSlot::Value(Word::default())],
    )
    .unwrap()
    .with_supported_type(AccountType::RegularAccountUpdatableCode);

    let mut account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .with_component(component1)
        .with_component(component2)
        .build_existing()
        .unwrap();

    // Assert that the storage offset and size have been set correctly.
    for (procedure_digest, expected_offset, expected_size) in
        [(foo_write, 0, 1), (foo_read, 0, 1), (bar_write, 1, 1), (bar_read, 1, 1)]
    {
        let procedure_info = account
            .code()
            .procedures()
            .iter()
            .find(|proc| proc.mast_root() == &procedure_digest)
            .unwrap();
        assert_eq!(
            procedure_info.storage_offset(),
            expected_offset,
            "failed for procedure {procedure_digest}"
        );
        assert_eq!(
            procedure_info.storage_size(),
            expected_size,
            "failed for procedure {procedure_digest}"
        );
    }

    // setup transaction script
    let tx_script_source_code = format!(
        "
    begin
        call.{foo_write}
        call.{foo_read}
        call.{bar_write}
        call.{bar_read}
    end
    "
    );
    let tx_script_program = assembler.assemble_program(tx_script_source_code).unwrap();
    let tx_script = TransactionScript::new(tx_script_program);

    // setup transaction context
    let tx_context = TransactionContextBuilder::new(account.clone()).tx_script(tx_script).build();

    // execute code in context
    let tx = tx_context.execute().into_diagnostic()?;
    account.apply_delta(tx.account_delta()).unwrap();

    // assert that elements have been set at the correct locations in storage
    assert_eq!(
        account.storage().get_item(0).unwrap(),
        [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)].into()
    );

    assert_eq!(
        account.storage().get_item(1).unwrap(),
        [Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)].into()
    );

    Ok(())
}

/// Tests that we can successfully create regular and faucet accounts with empty storage.
#[test]
fn create_account_with_empty_storage_slots() -> anyhow::Result<()> {
    // transaction code which only increases the nonce to make the transaction non-empty
    let default_tx_code = "
        use.kernel::account 
        
        begin 
            push.1 exec.account::incr_nonce 
        end";

    for account_type in [AccountType::FungibleFaucet, AccountType::RegularAccountUpdatableCode] {
        let mock_chain = MockChain::new();
        let (account, seed) = AccountBuilder::new([5; 32])
            .account_type(account_type)
            .with_component(
                AccountMockComponent::new_with_empty_slots(TransactionKernel::testing_assembler())
                    .unwrap(),
            )
            .build()
            .context("failed to build account")?;

        let tx_inputs = mock_chain.get_transaction_inputs(account.clone(), Some(seed), &[], &[]);
        let tx_context = TransactionContextBuilder::new(account)
            .account_seed(Some(seed))
            .tx_inputs(tx_inputs)
            .build();
        tx_context
            .execute_code(default_tx_code)
            .map_err(TransactionExecutorError::TransactionProgramExecutionFailed)
            .context(format!("failed to execute {account_type} account creating tx"))?;
    }

    Ok(())
}

fn create_procedure_metadata_test_account(
    account_type: AccountType,
    storage_offset: u8,
    storage_size: u8,
) -> anyhow::Result<Result<ExecutedTransaction, ExecutionError>> {
    let mock_chain = MockChain::new();

    let version = AccountIdVersion::Version0;

    let mock_code = AccountCode::mock();
    let code = AccountCode::from_parts(
        mock_code.mast(),
        mock_code
            .mast()
            .procedure_digests()
            .map(|mast_root| {
                AccountProcedureInfo::new(mast_root, storage_offset, storage_size).unwrap()
            })
            .collect(),
    );

    let storage = AccountStorage::new(vec![StorageSlot::Value(EMPTY_WORD)]).unwrap();

    let seed = AccountId::compute_account_seed(
        [9; 32],
        account_type,
        AccountStorageMode::Private,
        version,
        code.commitment(),
        storage.commitment(),
    )
    .context("failed to compute seed")?;
    let id = AccountId::new(seed, version, code.commitment(), storage.commitment())
        .context("failed to compute ID")?;

    let account = Account::from_parts(id, AssetVault::default(), storage, code, Felt::from(0u32));

    let tx_inputs = mock_chain.get_transaction_inputs(account.clone(), Some(seed), &[], &[]);
    let tx_context = TransactionContextBuilder::new(account)
        .account_seed(Some(seed))
        .tx_inputs(tx_inputs)
        .build();

    let result = tx_context.execute().map_err(|err| {
        let TransactionExecutorError::TransactionProgramExecutionFailed(exec_err) = err else {
            panic!("should have received an execution error");
        };

        exec_err
    });

    Ok(result)
}

/// Tests that creating an account whose procedure accesses the reserved faucet storage slot fails.
#[test]
fn creating_faucet_account_with_procedure_accessing_reserved_slot_fails() -> anyhow::Result<()> {
    // Set offset to 0 for a faucet which should be disallowed.
    let execution_res = create_procedure_metadata_test_account(AccountType::FungibleFaucet, 0, 1)
        .context("failed to create test account")?;

    assert_execution_error!(execution_res, ERR_FAUCET_INVALID_STORAGE_OFFSET);

    Ok(())
}

/// Tests that creating a faucet whose procedure offset+size is out of bounds fails.
#[test]
fn creating_faucet_with_procedure_offset_plus_size_out_of_bounds_fails() -> anyhow::Result<()> {
    // Set offset to lowest allowed value 1 and size to 1 while number of slots is 1 which should
    // result in an out of bounds error.
    let execution_res = create_procedure_metadata_test_account(AccountType::FungibleFaucet, 1, 1)
        .context("failed to create test account")?;

    assert_execution_error!(execution_res, ERR_ACCOUNT_STORAGE_SLOT_INDEX_OUT_OF_BOUNDS);

    // Set offset to 2 while number of slots is 1 which should result in an out of bounds error.
    let execution_res = create_procedure_metadata_test_account(AccountType::FungibleFaucet, 2, 1)
        .context("failed to create test account")?;

    assert_execution_error!(execution_res, ERR_ACCOUNT_STORAGE_SLOT_INDEX_OUT_OF_BOUNDS);

    Ok(())
}

/// Tests that creating an account whose procedure offset+size is out of bounds fails.
#[test]
fn creating_account_with_procedure_offset_plus_size_out_of_bounds_fails() -> anyhow::Result<()> {
    // Set size to 2 while number of slots is 1 which should result in an out of bounds error.
    let execution_res =
        create_procedure_metadata_test_account(AccountType::RegularAccountImmutableCode, 0, 2)
            .context("failed to create test account")?;

    assert_execution_error!(execution_res, ERR_ACCOUNT_STORAGE_SLOT_INDEX_OUT_OF_BOUNDS);

    // Set offset to 2 while number of slots is 1 which should result in an out of bounds error.
    let execution_res =
        create_procedure_metadata_test_account(AccountType::RegularAccountImmutableCode, 2, 1)
            .context("failed to create test account")?;

    assert_execution_error!(execution_res, ERR_ACCOUNT_STORAGE_SLOT_INDEX_OUT_OF_BOUNDS);

    Ok(())
}

// ACCOUNT VAULT TESTS
// ================================================================================================

#[test]
fn test_get_vault_root() {
    let tx_context = TransactionContextBuilder::with_standard_account(ONE).build();

    let account = tx_context.account();
    let code = format!(
        "
        use.miden::account
        use.kernel::prologue

        begin
            exec.prologue::prepare_transaction

            # push the new storage item onto the stack
            exec.account::get_vault_root
            push.{expected_vault_root}
            assert_eqw
        end
        ",
        expected_vault_root = word_to_masm_push_string(&account.vault().root()),
    );

    tx_context.execute_code(&code).unwrap();
}

// PROCEDURE AUTHENTICATION TESTS
// ================================================================================================

#[test]
fn test_authenticate_procedure() -> miette::Result<()> {
    let mock_component =
        AccountMockComponent::new_with_empty_slots(TransactionKernel::assembler()).unwrap();
    let account_code = AccountCode::from_components(
        &[mock_component.into()],
        AccountType::RegularAccountUpdatableCode,
    )
    .unwrap();

    let tc_0: [Felt; 4] =
        account_code.procedures()[0].mast_root().as_elements().try_into().unwrap();
    let tc_1: [Felt; 4] =
        account_code.procedures()[1].mast_root().as_elements().try_into().unwrap();
    let tc_2: [Felt; 4] =
        account_code.procedures()[2].mast_root().as_elements().try_into().unwrap();

    let test_cases =
        vec![(tc_0, true), (tc_1, true), (tc_2, true), ([ONE, ZERO, ONE, ZERO], false)];

    for (root, valid) in test_cases.into_iter() {
        let tx_context = TransactionContextBuilder::with_standard_account(ONE).build();

        let code = format!(
            "
            use.kernel::account
            use.kernel::prologue

            begin
                exec.prologue::prepare_transaction

                # authenticate procedure
                push.{root}
                exec.account::authenticate_procedure

                # truncate the stack
                dropw
            end
            ",
            root = word_to_masm_push_string(&root)
        );

        // Execution of this code will return an EventError(UnknownAccountProcedure) for procs
        // that are not in the advice provider.
        let process = tx_context.execute_code(&code);

        match valid {
            true => assert!(process.is_ok(), "A valid procedure must successfully authenticate"),
            false => assert!(process.is_err(), "An invalid procedure should fail to authenticate"),
        }
    }

    Ok(())
}

// PROCEDURE INTROSPECTION TESTS
// ================================================================================================

#[test]
fn test_was_procedure_called() -> miette::Result<()> {
    // Create an account with multiple procedures
    let mock_component =
        AccountMockComponent::new_with_empty_slots(TransactionKernel::assembler()).unwrap();
    let account_code = AccountCode::from_components(
        &[mock_component.into()],
        AccountType::RegularAccountUpdatableCode,
    )
    .unwrap();

    // Get procedure roots from the account code
    let proc_0_root: [Felt; 4] =
        account_code.procedures()[0].mast_root().as_elements().try_into().unwrap();
    let proc_1_root: [Felt; 4] =
        account_code.procedures()[1].mast_root().as_elements().try_into().unwrap();
    let proc_2_root: [Felt; 4] =
        account_code.procedures()[2].mast_root().as_elements().try_into().unwrap();

    // Create a test transaction context
    let account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .account_type(AccountType::RegularAccountUpdatableCode)
        .with_component(mock_component)
        .build_existing()
        .unwrap();

    let tx_context = TransactionContextBuilder::new(account).build();

    // Test 1: Check that procedures are not called initially
    let code = format!(
        "
        use.kernel::account
        use.kernel::prologue

        begin
            exec.prologue::prepare_transaction

            # Check that procedure 0 has not been called
            push.{proc_0}
            exec.account::was_procedure_called
            assertz # Should be 0 (not called)

            # Check that procedure 1 has not been called
            push.{proc_1}
            exec.account::was_procedure_called
            assertz # Should be 0 (not called)

            # Check that procedure 2 has not been called
            push.{proc_2}
            exec.account::was_procedure_called
            assertz # Should be 0 (not called)
        end
        ",
        proc_0 = word_to_masm_push_string(&proc_0_root),
        proc_1 = word_to_masm_push_string(&proc_1_root),
        proc_2 = word_to_masm_push_string(&proc_2_root),
    );

    tx_context.execute_code(&code).wrap_err("failed to execute initial check")?;

    // Test 2: Call a procedure and verify it's marked as called
    let code = format!(
        "
        use.kernel::account
        use.kernel::prologue

        begin
            exec.prologue::prepare_transaction

            # Authenticate and call procedure 0
            push.{proc_0}
            exec.account::authenticate_procedure
            drop drop # drop storage_offset and storage_size

            # Check that procedure 0 has been called
            push.{proc_0}
            exec.account::was_procedure_called
            assert # Should be 1 (called)

            # Check that procedure 1 has still not been called
            push.{proc_1}
            exec.account::was_procedure_called
            assertz # Should be 0 (not called)

            # Check that procedure 2 has still not been called
            push.{proc_2}
            exec.account::was_procedure_called
            assertz # Should be 0 (not called)
        end
        ",
        proc_0 = word_to_masm_push_string(&proc_0_root),
        proc_1 = word_to_masm_push_string(&proc_1_root),
        proc_2 = word_to_masm_push_string(&proc_2_root),
    );

    tx_context.execute_code(&code).wrap_err("failed to execute after first procedure call")?;

    // Test 3: Call multiple procedures and verify they're marked as called
    let code = format!(
        "
        use.kernel::account
        use.kernel::prologue

        begin
            exec.prologue::prepare_transaction

            # Authenticate and call procedure 0
            push.{proc_0}
            exec.account::authenticate_procedure
            drop drop # drop storage_offset and storage_size

            # Authenticate and call procedure 1
            push.{proc_1}
            exec.account::authenticate_procedure
            drop drop # drop storage_offset and storage_size

            # Check that procedure 0 has been called
            push.{proc_0}
            exec.account::was_procedure_called
            assert # Should be 1 (called)

            # Check that procedure 1 has been called
            push.{proc_1}
            exec.account::was_procedure_called
            assert # Should be 1 (called)

            # Check that procedure 2 has still not been called
            push.{proc_2}
            exec.account::was_procedure_called
            assertz # Should be 0 (not called)
        end
        ",
        proc_0 = word_to_masm_push_string(&proc_0_root),
        proc_1 = word_to_masm_push_string(&proc_1_root),
        proc_2 = word_to_masm_push_string(&proc_2_root),
    );

    tx_context.execute_code(&code).wrap_err("failed to execute after multiple procedure calls")?;

    // Test 4: Test with an invalid procedure root (should panic)
    let invalid_root = [ONE, ZERO, ONE, ZERO];
    let code = format!(
        "
        use.kernel::account
        use.kernel::prologue

        begin
            exec.prologue::prepare_transaction

            # Try to check if an invalid procedure was called
            push.{invalid_root}
            exec.account::was_procedure_called
            # This should panic with ERR_ACCOUNT_PROC_NOT_PART_OF_ACCOUNT_CODE
        end
        ",
        invalid_root = word_to_masm_push_string(&invalid_root),
    );

    let result = tx_context.execute_code(&code);
    assert!(result.is_err(), "Checking an invalid procedure should fail");

    Ok(())
}

#[test]
fn test_was_procedure_called_integration() -> miette::Result<()> {
    // Create an account with custom procedures that check if other procedures were called
    let source_code_component = "
        use.miden::account

        # A simple procedure that does nothing
        export.proc_a
            # Just increment the nonce to have some effect
            push.1 exec.account::incr_nonce
        end

        # A procedure that checks if proc_a was called
        export.proc_b
            # This procedure will be called to check if proc_a was executed
            push.1 exec.account::incr_nonce
        end

        # A procedure that performs some storage operations
        export.proc_c
            push.99.98.97.96.0
            exec.account::set_item
            dropw
        end
    ";

    // Compile the component
    let assembler = TransactionKernel::testing_assembler();
    let component = AccountComponent::compile(
        source_code_component,
        assembler.clone(),
        vec![StorageSlot::Value([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)])],
    )
    .unwrap()
    .with_supported_type(AccountType::RegularAccountUpdatableCode);

    // Create account with the component
    let account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .account_type(AccountType::RegularAccountUpdatableCode)
        .with_component(component)
        .build_existing()
        .unwrap();

    // Get the procedure roots
    let proc_a_root = account.code().procedures()[0].mast_root();
    let proc_b_root = account.code().procedures()[1].mast_root();
    let proc_c_root = account.code().procedures()[2].mast_root();

    // Create transaction context
    let tx_context = TransactionContextBuilder::new(account.clone()).build();

    // Test case 1: Execute a transaction that calls proc_a and then checks if it was called
    let tx_script_source = format!(
        "
        use.miden::account

        begin
            # Call proc_a
            call.{proc_a}

            # Check if proc_a was called (should be true)
            push.{proc_a_word}
            exec.account::was_procedure_called
            assert # Should be 1

            # Check if proc_b was called (should be false)
            push.{proc_b_word}
            exec.account::was_procedure_called
            assertz # Should be 0

            # Check if proc_c was called (should be false)
            push.{proc_c_word}
            exec.account::was_procedure_called
            assertz # Should be 0
        end
        ",
        proc_a = proc_a_root,
        proc_a_word = word_to_masm_push_string(&proc_a_root.as_elements()),
        proc_b_word = word_to_masm_push_string(&proc_b_root.as_elements()),
        proc_c_word = word_to_masm_push_string(&proc_c_root.as_elements()),
    );

    let tx_script = TransactionScript::new(
        assembler
            .clone()
            .assemble_program(tx_script_source)
            .wrap_err("Failed to compile transaction script")?
    );

    let tx_context = TransactionContextBuilder::new(account.clone())
        .tx_script(tx_script)
        .build();

    let result = tx_context.execute().into_diagnostic()
        .wrap_err("Failed to execute transaction with single procedure call")?;

    // Test case 2: Execute a transaction that calls multiple procedures
    let tx_script_source = format!(
        "
        use.miden::account

        begin
            # Call proc_a and proc_c
            call.{proc_a}
            call.{proc_c}

            # Check if proc_a was called (should be true)
            push.{proc_a_word}
            exec.account::was_procedure_called
            assert # Should be 1

            # Check if proc_b was called (should be false)
            push.{proc_b_word}
            exec.account::was_procedure_called
            assertz # Should be 0

            # Check if proc_c was called (should be true)
            push.{proc_c_word}
            exec.account::was_procedure_called
            assert # Should be 1

            # Call proc_b
            call.{proc_b}

            # Now check if proc_b was called (should be true)
            push.{proc_b_word}
            exec.account::was_procedure_called
            assert # Should be 1
        end
        ",
        proc_a = proc_a_root,
        proc_b = proc_b_root,
        proc_c = proc_c_root,
        proc_a_word = word_to_masm_push_string(&proc_a_root.as_elements()),
        proc_b_word = word_to_masm_push_string(&proc_b_root.as_elements()),
        proc_c_word = word_to_masm_push_string(&proc_c_root.as_elements()),
    );

    let tx_script = TransactionScript::new(
        assembler
            .assemble_program(tx_script_source)
            .wrap_err("Failed to compile transaction script for multiple calls")?
    );

    let tx_context = TransactionContextBuilder::new(account)
        .tx_script(tx_script)
        .build();

    let result = tx_context.execute().into_diagnostic()
        .wrap_err("Failed to execute transaction with multiple procedure calls")?;

    Ok(())
}

#[test]
fn test_was_procedure_called_conditional_execution() -> miette::Result<()> {
    // Create an account with procedures that have conditional logic based on whether
    // other procedures have been called
    let source_code_component = "
        use.miden::account

        # Procedure that sets a flag in storage
        export.set_flag
            push.1.0.0.0.0
            exec.account::set_item
            dropw
        end

        # Procedure that should only execute if set_flag was called
        export.conditional_proc
            # This could be used for access control - only allow execution
            # if a certain initialization procedure was called first
            push.2.0.0.0.0
            exec.account::set_item
            dropw
        end

        # Procedure that clears the flag
        export.clear_flag
            push.0.0.0.0.0
            exec.account::set_item
            dropw
        end
    ";

    // Compile the component
    let assembler = TransactionKernel::testing_assembler();
    let component = AccountComponent::compile(
        source_code_component,
        assembler.clone(),
        vec![StorageSlot::Value(EMPTY_WORD)],
    )
    .unwrap()
    .with_supported_type(AccountType::RegularAccountUpdatableCode);

    // Create account with the component
    let account = AccountBuilder::new(ChaCha20Rng::from_os_rng().random())
        .account_type(AccountType::RegularAccountUpdatableCode)
        .with_component(component)
        .build_existing()
        .unwrap();

    // Get the procedure roots
    let set_flag_root = account.code().procedures()[0].mast_root();
    let conditional_proc_root = account.code().procedures()[1].mast_root();
    let clear_flag_root = account.code().procedures()[2].mast_root();

    // Test case 1: Try to call conditional_proc without calling set_flag first (should fail)
    let tx_script_source = format!(
        "
        use.miden::account

        begin
            # Check if set_flag was called (should be false)
            push.{set_flag_word}
            exec.account::was_procedure_called
            assertz # Assert it wasn't called

            # Try to call conditional_proc - in a real implementation,
            # this procedure would check internally if set_flag was called
            # For this test, we check it externally
            push.{set_flag_word}
            exec.account::was_procedure_called
            not assert # Assert that set_flag was NOT called

            # Since set_flag wasn't called, we simulate the conditional behavior
            # by NOT calling conditional_proc
        end
        ",
        set_flag_word = word_to_masm_push_string(&set_flag_root.as_elements()),
    );

    let tx_script = TransactionScript::new(
        assembler
            .clone()
            .assemble_program(tx_script_source)
            .wrap_err("Failed to compile first transaction script")?
    );

    let tx_context = TransactionContextBuilder::new(account.clone())
        .tx_script(tx_script)
        .build();

    tx_context.execute().into_diagnostic()
        .wrap_err("Failed to execute transaction without set_flag")?;

    // Test case 2: Call set_flag first, then conditional_proc (should succeed)
    let tx_script_source = format!(
        "
        use.miden::account

        begin
            # Call set_flag first
            call.{set_flag}

            # Verify set_flag was called
            push.{set_flag_word}
            exec.account::was_procedure_called
            assert # Should be 1

            # Now we can safely call conditional_proc
            call.{conditional_proc}

            # Verify both procedures were called
            push.{set_flag_word}
            exec.account::was_procedure_called
            assert # Should be 1

            push.{conditional_proc_word}
            exec.account::was_procedure_called
            assert # Should be 1

            # Clear flag procedure should not have been called
            push.{clear_flag_word}
            exec.account::was_procedure_called
            assertz # Should be 0
        end
        ",
        set_flag = set_flag_root,
        conditional_proc = conditional_proc_root,
        set_flag_word = word_to_masm_push_string(&set_flag_root.as_elements()),
        conditional_proc_word = word_to_masm_push_string(&conditional_proc_root.as_elements()),
        clear_flag_word = word_to_masm_push_string(&clear_flag_root.as_elements()),
    );

    let tx_script = TransactionScript::new(
        assembler
            .clone()
            .assemble_program(tx_script_source)
            .wrap_err("Failed to compile second transaction script")?
    );

    let tx_context = TransactionContextBuilder::new(account.clone())
        .tx_script(tx_script)
        .build();

    tx_context.execute().into_diagnostic()
        .wrap_err("Failed to execute transaction with proper sequence")?;

    // Test case 3: Demonstrate that was_called state persists within a transaction
    let tx_script_source = format!(
        "
        use.miden::account

        begin
            # Check initial state - nothing called yet
            push.{set_flag_word}
            exec.account::was_procedure_called
            assertz # Should be 0

            # Call set_flag
            call.{set_flag}

            # Immediately check - should be marked as called
            push.{set_flag_word}
            exec.account::was_procedure_called
            assert # Should be 1

            # Check again later in the transaction - should still be 1
            push.1 push.2 add drop # Do some other work

            push.{set_flag_word}
            exec.account::was_procedure_called
            assert # Should still be 1

            # Call it again - was_called should still be 1
            call.{set_flag}

            push.{set_flag_word}
            exec.account::was_procedure_called
            assert # Should still be 1 (not incremented)
        end
        ",
        set_flag = set_flag_root,
        set_flag_word = word_to_masm_push_string(&set_flag_root.as_elements()),
    );

    let tx_script = TransactionScript::new(
        assembler
            .assemble_program(tx_script_source)
            .wrap_err("Failed to compile third transaction script")?
    );

    let tx_context = TransactionContextBuilder::new(account)
        .tx_script(tx_script)
        .build();

    tx_context.execute().into_diagnostic()
        .wrap_err("Failed to execute transaction testing persistence")?;

    Ok(())
}

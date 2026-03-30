#!/usr/bin/env python3

import json
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parent
WITNESS_PATH = ROOT / "block_24740084_witness.json"
ACCOUNT_PATH = ROOT / "account_snapshot_parent.json"
STORAGE_PATH = ROOT / "storage_snapshot_parent.json"
BLOCK_HASHES_PATH = ROOT / "block_hashes_parent_window.json"
MAIN_RS_PATH = ROOT / "src" / "main.rs"


def rs_str(value: str) -> str:
    return json.dumps(value)


def rs_opt_str(value: str | None) -> str:
    return "None" if value is None else f"Some({rs_str(value)})"


def state_diff_to_value(diff):
    if diff == "=":
        return None
    if "*" in diff:
        return diff["*"]["to"]
    if "+" in diff:
        return diff["+"]
    raise ValueError(f"unsupported state diff shape: {diff}")


def emit_access_list(access_list: list[dict]) -> str:
    if not access_list:
        return "&[]"
    items = []
    for item in access_list:
        keys = "\n".join(
            f"                {rs_str(slot)}," for slot in item["storageKeys"]
        )
        items.append(
            """
        RawAccessListItem {
            address: %s,
            storage_keys: &[
%s
            ],
        },"""
            % (rs_str(item["address"]), keys)
        )
    return "&[" + "\n".join(items) + "\n    ]"


def emit_transactions(transactions: list[dict]) -> str:
    rows = []
    for tx in transactions:
        rows.append(
            """
    RawTransaction {
        hash: %s,
        from: %s,
        to: %s,
        nonce: %s,
        gas_limit: %s,
        gas_price: %s,
        max_priority_fee_per_gas: %s,
        value: %s,
        input: %s,
        tx_type: %s,
        chain_id: %s,
        access_list: %s,
    },"""
            % (
                rs_str(tx["hash"]),
                rs_str(tx["from"]),
                rs_opt_str(tx.get("to")),
                rs_str(tx["nonce"]),
                rs_str(tx["gas"]),
                rs_str(tx["maxFeePerGas"] if tx["type"] != "0x0" else tx["gasPrice"]),
                rs_str(tx.get("maxPriorityFeePerGas", "0x0")),
                rs_str(tx["value"]),
                rs_str(tx["input"]),
                rs_str(tx["type"]),
                rs_str(tx["chainId"]),
                emit_access_list(tx.get("accessList", [])),
            )
        )
    return "\n".join(rows)


def emit_accounts(accounts: dict[str, dict]) -> str:
    rows = []
    for address, info in sorted(accounts.items()):
        rows.append(
            """
    RawAccountInfo {
        address: %s,
        balance: %s,
        nonce: %s,
        code: %s,
    },"""
            % (
                rs_str(address),
                rs_str(info["balance"]),
                rs_str(info["nonce"]),
                rs_str(info["code"]),
            )
        )
    return "\n".join(rows)


def emit_storage(storage: dict[str, dict]) -> str:
    rows = []
    for address, slots in sorted(storage.items()):
        for slot, value in sorted(slots.items()):
            rows.append(
                """
    RawStorageValue {
        address: %s,
        slot: %s,
        value: %s,
    },"""
                % (rs_str(address), rs_str(slot), rs_str(value))
            )
    return "\n".join(rows)


def emit_block_hashes(block_hashes: dict[str, str]) -> str:
    rows = []
    for number, block_hash in sorted(
        block_hashes.items(), key=lambda item: int(item[0])
    ):
        rows.append(
            """
    RawBlockHash {
        number: %s,
        hash: %s,
    },"""
            % (rs_str(hex(int(number))), rs_str(block_hash))
        )
    return "\n".join(rows)


with WITNESS_PATH.open() as f:
    witness = json.load(f)

with ACCOUNT_PATH.open() as f:
    accounts = json.load(f)

with STORAGE_PATH.open() as f:
    storage = json.load(f)

with BLOCK_HASHES_PATH.open() as f:
    block_hashes = json.load(f)

code = f"""#![cfg_attr(target_arch = "riscv32", no_main)]
#![cfg_attr(target_arch = "riscv32", no_std)]

#[cfg(target_arch = "riscv32")]
guest::guest_main!(main);

#[cfg(target_arch = "riscv32")]
fn main() {{
    guest::write_result(0);
}}

#[cfg(not(target_arch = "riscv32"))]
use std::collections::HashMap;

#[cfg(not(target_arch = "riscv32"))]
use std::sync::Mutex;

#[cfg(not(target_arch = "riscv32"))]
use revm::{{
    context::{{transaction::AccessListItem, BlockEnv, CfgEnv, TxEnv}},
    context_interface::ContextTr,
    database::CacheDB,
    database_interface::{{DBErrorMarker, DatabaseRef}},
    primitives::{{Address, Bytes, FixedBytes, TxKind, B256, U256}},
    state::{{AccountInfo, Bytecode}},
    Context, ExecuteCommitEvm, MainBuilder, MainContext,
}};

#[cfg(not(target_arch = "riscv32"))]
#[derive(Clone, Copy)]
struct RawBlockEnv {{
    number: &'static str,
    beneficiary: &'static str,
    timestamp: &'static str,
    gas_limit: &'static str,
    base_fee_per_gas: &'static str,
    difficulty: &'static str,
    prevrandao: &'static str,
}}

#[cfg(not(target_arch = "riscv32"))]
#[derive(Clone, Copy)]
struct RawAccessListItem {{
    address: &'static str,
    storage_keys: &'static [&'static str],
}}

#[cfg(not(target_arch = "riscv32"))]
#[derive(Clone, Copy)]
struct RawTransaction {{
    hash: &'static str,
    from: &'static str,
    to: Option<&'static str>,
    nonce: &'static str,
    gas_limit: &'static str,
    gas_price: &'static str,
    max_priority_fee_per_gas: &'static str,
    value: &'static str,
    input: &'static str,
    tx_type: &'static str,
    chain_id: &'static str,
    access_list: &'static [RawAccessListItem],
}}

#[cfg(not(target_arch = "riscv32"))]
#[derive(Clone, Copy)]
struct RawAccountInfo {{
    address: &'static str,
    balance: &'static str,
    nonce: &'static str,
    code: &'static str,
}}

#[cfg(not(target_arch = "riscv32"))]
#[derive(Clone, Copy)]
struct RawStorageValue {{
    address: &'static str,
    slot: &'static str,
    value: &'static str,
}}

#[cfg(not(target_arch = "riscv32"))]
#[derive(Clone, Copy)]
struct RawBlockHash {{
    number: &'static str,
    hash: &'static str,
}}

#[cfg(not(target_arch = "riscv32"))]
const BLOCK_ENV: RawBlockEnv = RawBlockEnv {{
    number: {rs_str(witness["block_env"]["number"])},
    beneficiary: {rs_str(witness["block_env"]["coinbase"])},
    timestamp: {rs_str(witness["block_env"]["timestamp"])},
    gas_limit: {rs_str(witness["block_env"]["gas_limit"])},
    base_fee_per_gas: {rs_str(witness["block_env"]["base_fee_per_gas"])},
    difficulty: {rs_str(witness["block_env"]["difficulty"])},
    prevrandao: {rs_str(witness["block_env"]["prevrandao"])},
}};

#[cfg(not(target_arch = "riscv32"))]
const TRANSACTIONS: &[RawTransaction] = &[
{emit_transactions(witness["transactions"])}
];

#[cfg(not(target_arch = "riscv32"))]
const PRESTATE_ACCOUNTS: &[RawAccountInfo] = &[
{emit_accounts(accounts)}
];

#[cfg(not(target_arch = "riscv32"))]
const PRESTATE_STORAGE: &[RawStorageValue] = &[
{emit_storage(storage)}
];

#[cfg(not(target_arch = "riscv32"))]
const BLOCK_HASHES: &[RawBlockHash] = &[
{emit_block_hashes(block_hashes)}
];

#[cfg(not(target_arch = "riscv32"))]
#[derive(Debug)]
enum WitnessDbError {{
    MissingCode(B256),
}}

#[cfg(not(target_arch = "riscv32"))]
impl std::fmt::Display for WitnessDbError {{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{
        match self {{
            Self::MissingCode(code_hash) => write!(f, "missing code in hardcoded witness: {{code_hash}}"),
        }}
    }}
}}

#[cfg(not(target_arch = "riscv32"))]
impl std::error::Error for WitnessDbError {{}}

#[cfg(not(target_arch = "riscv32"))]
impl DBErrorMarker for WitnessDbError {{}}

#[cfg(not(target_arch = "riscv32"))]
struct HardcodedDb {{
    accounts: HashMap<Address, Option<AccountInfo>>,
    storage: HashMap<(Address, U256), U256>,
    contracts: HashMap<B256, Bytecode>,
    block_hashes: HashMap<u64, B256>,
    missing_reads: Mutex<Vec<String>>,
}}

#[cfg(not(target_arch = "riscv32"))]
impl HardcodedDb {{
    fn new() -> Self {{
        let mut accounts = HashMap::new();
        let mut contracts = HashMap::new();

        for raw in PRESTATE_ACCOUNTS {{
            let address = parse_address(raw.address);
            let balance = parse_u256(raw.balance);
            let nonce = parse_u64(raw.nonce);
            let has_code = raw.code != "0x";
            let exists = has_code || balance != U256::ZERO || nonce != 0;

            if !exists {{
                accounts.insert(address, None);
                continue;
            }}

            let mut info = AccountInfo::default().with_balance(balance).with_nonce(nonce);
            if has_code {{
                let code = Bytecode::new_raw(parse_bytes(raw.code));
                info = info.with_code(code.clone());
                contracts.insert(info.code_hash, code);
            }}
            accounts.insert(address, Some(info));
        }}

        let mut storage = HashMap::new();
        for raw in PRESTATE_STORAGE {{
            storage.insert(
                (parse_address(raw.address), parse_u256(raw.slot)),
                parse_u256(raw.value),
            );
        }}

        let mut block_hashes = HashMap::new();
        for raw in BLOCK_HASHES {{
            block_hashes.insert(parse_u64(raw.number), parse_b256(raw.hash));
        }}

        Self {{
            accounts,
            storage,
            contracts,
            block_hashes,
            missing_reads: Mutex::new(Vec::new()),
        }}
    }}

    fn clear_missing_reads(&self) {{
        self.missing_reads.lock().unwrap().clear();
    }}

    fn take_missing_reads(&self) -> Vec<String> {{
        let mut missing = self.missing_reads.lock().unwrap();
        std::mem::take(&mut *missing)
    }}

    fn note_missing_read(&self, value: String) {{
        self.missing_reads.lock().unwrap().push(value);
    }}
}}

#[cfg(not(target_arch = "riscv32"))]
impl DatabaseRef for HardcodedDb {{
    type Error = WitnessDbError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {{
        if let Some(info) = self.accounts.get(&address) {{
            Ok(info.clone())
        }} else {{
            self.note_missing_read(format!("account: {{address}}"));
            Ok(None)
        }}
    }}

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {{
        self.contracts
            .get(&code_hash)
            .cloned()
            .ok_or(WitnessDbError::MissingCode(code_hash))
    }}

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {{
        if let Some(value) = self.storage.get(&(address, index)) {{
            Ok(*value)
        }} else {{
            self.note_missing_read(format!("storage: {{address}}[{{index:#x}}]"));
            Ok(U256::ZERO)
        }}
    }}

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {{
        Ok(self.block_hashes.get(&number).copied().unwrap_or_default())
    }}
}}

#[cfg(not(target_arch = "riscv32"))]
fn parse_address(hex: &str) -> Address {{
    hex.parse().unwrap()
}}

#[cfg(not(target_arch = "riscv32"))]
fn parse_b256(hex: &str) -> FixedBytes<32> {{
    hex.parse().unwrap()
}}

#[cfg(not(target_arch = "riscv32"))]
fn parse_u64(hex: &str) -> u64 {{
    u64::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap()
}}

#[cfg(not(target_arch = "riscv32"))]
fn parse_u128(hex: &str) -> u128 {{
    u128::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap()
}}

#[cfg(not(target_arch = "riscv32"))]
fn parse_u256(hex: &str) -> U256 {{
    hex.parse().unwrap()
}}

#[cfg(not(target_arch = "riscv32"))]
fn parse_bytes(hex: &str) -> Bytes {{
    hex.parse().unwrap()
}}

#[cfg(not(target_arch = "riscv32"))]
fn build_block_env() -> BlockEnv {{
    let mut block = BlockEnv::default();
    block.number = parse_u256(BLOCK_ENV.number);
    block.beneficiary = parse_address(BLOCK_ENV.beneficiary);
    block.timestamp = parse_u256(BLOCK_ENV.timestamp);
    block.gas_limit = parse_u64(BLOCK_ENV.gas_limit);
    block.basefee = parse_u64(BLOCK_ENV.base_fee_per_gas);
    block.difficulty = parse_u256(BLOCK_ENV.difficulty);
    block.prevrandao = Some(parse_b256(BLOCK_ENV.prevrandao));
    block
}}

#[cfg(not(target_arch = "riscv32"))]
fn build_tx_env(raw: &RawTransaction) -> TxEnv {{
    let mut tx = TxEnv::default();
    tx.tx_type = parse_u64(raw.tx_type) as u8;
    tx.caller = parse_address(raw.from);
    tx.gas_limit = parse_u64(raw.gas_limit);
    tx.gas_price = parse_u128(raw.gas_price);
    tx.gas_priority_fee = if raw.tx_type == "0x0" {{
        None
    }} else {{
        Some(parse_u128(raw.max_priority_fee_per_gas))
    }};
    tx.kind = match raw.to {{
        Some(to) => TxKind::Call(parse_address(to)),
        None => TxKind::Create,
    }};
    tx.value = parse_u256(raw.value);
    tx.data = parse_bytes(raw.input);
    tx.nonce = parse_u64(raw.nonce);
    tx.chain_id = Some(parse_u64(raw.chain_id));
    tx.access_list = raw
        .access_list
        .iter()
        .map(|item| AccessListItem {{
            address: parse_address(item.address),
            storage_keys: item.storage_keys.iter().map(|slot| parse_b256(slot)).collect(),
        }})
        .collect::<Vec<_>>()
        .into();
    tx
}}

#[cfg(not(target_arch = "riscv32"))]
fn main() {{
    let db = CacheDB::new(HardcodedDb::new());
    let context = Context::mainnet().with_db(db);
    let mut evm = context.build_mainnet();
    evm.ctx.modify_cfg(|cfg: &mut CfgEnv| cfg.chain_id = 1);
    evm.ctx.modify_block(|block| *block = build_block_env());

    for tx in TRANSACTIONS {{
        evm.db().db.clear_missing_reads();
        evm.transact_commit(build_tx_env(tx)).unwrap_or_else(|error| {{
            let missing_reads = evm.db().db.take_missing_reads();
            if !missing_reads.is_empty() {{
                eprintln!("missing reads for failed tx {{}}:", tx.hash);
                for missing in missing_reads {{
                    eprintln!("  {{missing}}");
                }}
            }}
            panic!("failed to execute tx {{}}: {{error:?}}", tx.hash)
        }});

        let missing_reads = evm.db().db.take_missing_reads();
        if !missing_reads.is_empty() {{
            eprintln!("missing reads for tx {{}}:", tx.hash);
            for missing in missing_reads {{
                eprintln!("  {{missing}}");
            }}
        }}
    }}

    println!("replayed block {{}} with {{}} transactions", BLOCK_ENV.number, TRANSACTIONS.len());
}}
"""

host_marker = '#[cfg(not(target_arch = "riscv32"))]\nuse std::collections::HashMap;\n'
prelude, host_body = code.split(host_marker, 1)
host_body = "use std::collections::HashMap;\n" + host_body
host_body = host_body.replace('#[cfg(not(target_arch = "riscv32"))]\n', "")
host_body = host_body.replace("fn main() {", "pub fn main() {", 1)
code = (
    prelude
    + '\n#[cfg(not(target_arch = "riscv32"))]\nmod host {\n'
    + textwrap.indent(host_body, "    ")
    + '\n}\n\n#[cfg(not(target_arch = "riscv32"))]\nfn main() {\n    host::main();\n}\n'
)

MAIN_RS_PATH.write_text(code)
print(f"wrote {MAIN_RS_PATH}")

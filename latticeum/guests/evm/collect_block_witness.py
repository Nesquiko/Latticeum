#!/usr/bin/env python3

import json
import sys
import time
from pathlib import Path
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

RPC_ENDPOINTS = [
    "https://eth.llamarpc.com",
    "https://0xrpc.io/eth",
    "https://eth.api.pocket.network",
    "https://eth-mainnet.g.alchemy.com/v2/demo",
    "https://eth.blockrazor.xyz",
    "https://eth.meowrpc.com",
]

CHAIN_ID = 1
BLOCK_NUMBER = 24740084
BLOCK_TAG = hex(BLOCK_NUMBER)
DEFAULT_OUTPUT = Path(__file__).with_name(f"block_{BLOCK_NUMBER}_witness.json")
REQUEST_TIMEOUT_SECS = 45
RETRIES_PER_ENDPOINT = 2
TRACE_MODES = ["trace", "stateDiff"]


class RpcError(RuntimeError):
    pass


def rpc_call(endpoint: str, method: str, params: list[Any], request_id: int) -> Any:
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }
    ).encode("utf-8")
    request = Request(
        endpoint,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urlopen(request, timeout=REQUEST_TIMEOUT_SECS) as response:
        body = json.loads(response.read().decode("utf-8"))

    if "error" in body:
        error = body["error"]
        raise RpcError(f"{method} failed: {error.get('code')} {error.get('message')}")

    return body["result"]


def call_with_fallbacks(method: str, params: list[Any]) -> tuple[Any, str]:
    failures: list[str] = []
    request_id = 1

    for endpoint in RPC_ENDPOINTS:
        for attempt in range(1, RETRIES_PER_ENDPOINT + 1):
            try:
                result = rpc_call(endpoint, method, params, request_id)
                if result is None:
                    raise RpcError(f"{method} returned null")
                return result, endpoint
            except (RpcError, HTTPError, URLError, TimeoutError, OSError) as exc:
                failures.append(f"{endpoint} attempt {attempt}: {exc}")
                time.sleep(0.25)
            finally:
                request_id += 1

    raise RuntimeError(
        f"All RPC endpoints failed for {method}.\n" + "\n".join(failures)
    )


def get_block() -> tuple[dict[str, Any], str]:
    block, endpoint = call_with_fallbacks("eth_getBlockByNumber", [BLOCK_TAG, True])
    if int(block["number"], 16) != BLOCK_NUMBER:
        raise RuntimeError(f"Unexpected block number: {block['number']}")
    return block, endpoint


def get_receipts(tx_hashes: list[str]) -> tuple[list[dict[str, Any]], str, str]:
    try:
        receipts, endpoint = call_with_fallbacks("eth_getBlockReceipts", [BLOCK_TAG])
        if len(receipts) != len(tx_hashes):
            raise RuntimeError(
                f"eth_getBlockReceipts returned {len(receipts)} receipts for {len(tx_hashes)} txs"
            )
        return receipts, endpoint, "eth_getBlockReceipts"
    except RuntimeError:
        receipts = []
        used_endpoint = ""
        for tx_hash in tx_hashes:
            receipt, endpoint = call_with_fallbacks(
                "eth_getTransactionReceipt", [tx_hash]
            )
            receipts.append(receipt)
            used_endpoint = endpoint
        return receipts, used_endpoint, "eth_getTransactionReceipt"


def get_trace_bundle() -> tuple[list[dict[str, Any]], str]:
    traces, endpoint = call_with_fallbacks(
        "trace_replayBlockTransactions",
        [BLOCK_TAG, TRACE_MODES],
    )
    return traces, endpoint


def sort_by_transaction_index(items: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(items, key=lambda item: int(item["transactionIndex"], 16))


def build_block_env(block: dict[str, Any]) -> dict[str, Any]:
    return {
        "number": block["number"],
        "hash": block["hash"],
        "parent_hash": block["parentHash"],
        "timestamp": block["timestamp"],
        "gas_limit": block["gasLimit"],
        "base_fee_per_gas": block.get("baseFeePerGas", "0x0"),
        "coinbase": block["miner"],
        "difficulty": block.get("difficulty", "0x0"),
        "prevrandao": block.get("mixHash"),
        "blob_gas_used": block.get("blobGasUsed", "0x0"),
        "excess_blob_gas": block.get("excessBlobGas", "0x0"),
    }


def main() -> int:
    output_path = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_OUTPUT

    block, block_endpoint = get_block()
    transactions = sort_by_transaction_index(block["transactions"])
    tx_hashes = [tx["hash"] for tx in transactions]
    receipts, receipts_endpoint, receipts_method = get_receipts(tx_hashes)
    traces, trace_endpoint = get_trace_bundle()

    if len(traces) != len(transactions):
        raise RuntimeError(
            f"trace_replayBlockTransactions returned {len(traces)} results for {len(transactions)} txs"
        )

    result = {
        "meta": {
            "chain_id": CHAIN_ID,
            "block_number": BLOCK_NUMBER,
            "rpc_endpoints": RPC_ENDPOINTS,
            "collected_via": {
                "block": {
                    "rpc": block_endpoint,
                    "method": "eth_getBlockByNumber",
                },
                "receipts": {
                    "rpc": receipts_endpoint,
                    "method": receipts_method,
                },
                "trace": {
                    "rpc": trace_endpoint,
                    "method": "trace_replayBlockTransactions",
                    "modes": TRACE_MODES,
                },
            },
        },
        "block_env": build_block_env(block),
        "transactions": transactions,
        "receipts": sort_by_transaction_index(receipts),
        "prestate_witness": {
            "kind": "parity_state_diff",
            "transactions": traces,
        },
    }

    output_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {output_path}")
    print(f"transactions: {len(transactions)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

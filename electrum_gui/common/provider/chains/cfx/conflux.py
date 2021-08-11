import functools
import time
from typing import Any, List, Optional, Tuple, Union

import eth_abi
import eth_utils
from hexbytes import HexBytes

from electrum_gui.common.basic.functional.require import require, require_not_none
from electrum_gui.common.basic.request.exceptions import JsonRPCException
from electrum_gui.common.basic.request.json_rpc import JsonRPCRequest
from electrum_gui.common.provider.chains.cfx.sdk import cfx_address, consts
from electrum_gui.common.provider.chains.cfx.sdk.types import Drip, SponsorInfo
from electrum_gui.common.provider.chains.eth.clients import helper
from electrum_gui.common.provider.chains.eth.clients.geth import (
    InvalidContractAddress,
    _extract_eth_call_str_result,
    _hex2int,
)
from electrum_gui.common.provider.data import (
    Address,
    BlockHeader,
    ClientInfo,
    EstimatedTimeOnPrice,
    PricesPerUnit,
    Transaction,
    TransactionFee,
    TransactionInput,
    TransactionOutput,
    TransactionStatus,
    TxBroadcastReceipt,
    TxBroadcastReceiptCode,
)
from electrum_gui.common.provider.exceptions import FailedToGetGasPrices, TransactionNotFound
from electrum_gui.common.provider.interfaces import BatchGetAddressMixin, ClientInterface


class CFXClient(ClientInterface, BatchGetAddressMixin):
    EpochTag = consts.LATEST_STATE

    def __init__(self, url: str):
        self.rpc = JsonRPCRequest(url)

    def get_info(self) -> ClientInfo:
        the_latest_block = self.rpc.call("cfx_getBlockByEpochNumber", params=[self.EpochTag, False])
        return ClientInfo(
            "conflux",
            best_block_number=_hex2int(the_latest_block["epochNumber"]),
            is_ready=time.time() - _hex2int(the_latest_block["timestamp"]) < 120,
        )

    def get_epoch_number(self):
        resp = self.rpc.call("cfx_epochNumber")
        return _hex2int(resp)

    def get_address(self, address: str) -> Address:
        _balance, _nonce = self.rpc.batch_call(
            [
                ("cfx_getBalance", [address, self.EpochTag]),
                ("cfx_getNextNonce", [address, self.EpochTag]),
            ]
        )  # Maybe EpochTag refers to a different blocks in some case
        balance = _hex2int(_balance)
        nonce = _hex2int(_nonce)
        return Address(address=address, balance=balance, nonce=nonce, existing=(bool(balance) or bool(nonce)))

    def batch_get_address(self, addresses: List[str]) -> List[Address]:
        _call_body = []
        for address in addresses:
            _call_body.extend(
                [
                    ("cfx_getBalance", [address, self.EpochTag]),
                    ("cfx_getNextNonce", [address, self.EpochTag]),
                ]
            )
        result = self.rpc.batch_call(_call_body, timeout=10)

        _resp_body = []
        result_iterator = iter(result)
        for _address, _balance_str, _nonce_str in zip(addresses, result_iterator, result_iterator):
            _balance = _hex2int(_balance_str)
            _nonce = _hex2int(_nonce_str)
            _resp_body.append(
                Address(address=_address, balance=_balance, nonce=_nonce, existing=(bool(_balance) or bool(_nonce)))
            )
        return _resp_body

    def get_balance(self, address: str, token_address: Optional[str] = None) -> int:
        if token_address is None:
            return super(CFXClient, self).get_balance(address)
        else:
            address = cfx_address.Address(base32_address=address).hex_address
            call_balance_of = (
                "0x70a08231000000000000000000000000" + address[2:]
            )  # method_selector(balance_of) + byte32_pad(address)
            resp = self.cfx_call({"to": token_address, "data": call_balance_of})

            try:
                return _hex2int(resp[:66])
            except ValueError:
                return 0

    def cfx_call(self, call_data: dict) -> Any:
        return self.rpc.call("cfx_call", [call_data, self.EpochTag])

    def get_transaction_by_txid(self, txid: str) -> Transaction:
        tx, receipt = self.rpc.batch_call(
            [
                ("cfx_getTransactionByHash", [txid]),
                ("cfx_getTransactionReceipt", [txid]),
            ]
        )
        if not tx:
            raise TransactionNotFound(txid)
        else:
            require(txid == tx.get("hash"))

        if receipt:
            block_header = BlockHeader(
                block_hash=receipt.get("blockHash", ""),
                block_number=_hex2int(receipt.get("epochNumber", "0x0")),
                block_time=0,
            )
            status = (
                TransactionStatus.CONFIRM_SUCCESS
                if receipt.get("outcomeStatus") == "0x0"
                else TransactionStatus.CONFIRM_REVERTED
            )
            gas_used = _hex2int(receipt.get("gasUsed", "0x0"))
        else:
            block_header = None
            status = TransactionStatus.PENDING
            gas_used = None

        gas_limit = _hex2int(tx.get("gas", "0x0"))
        fee = TransactionFee(
            limit=gas_limit,
            used=gas_used or gas_limit,
            price_per_unit=_hex2int(tx.get("gasPrice", "0x0")),
        )
        sender = tx.get("from", "").lower()
        receiver = tx.get("to", "").lower()
        value = _hex2int(tx.get("value", "0x0"))

        return Transaction(
            txid=txid,
            inputs=[TransactionInput(address=sender, value=value)],
            outputs=[TransactionOutput(address=receiver, value=value)],
            status=status,
            block_header=block_header,
            fee=fee,
            nonce=_hex2int(tx["nonce"]),
        )

    def broadcast_transaction(self, raw_tx: str) -> TxBroadcastReceipt:
        try:
            txid = self.rpc.call("cfx_sendRawTransaction", params=[raw_tx])
            return TxBroadcastReceipt(
                txid=txid,
                is_success=True,
                receipt_code=TxBroadcastReceiptCode.SUCCESS,
            )
        except JsonRPCException as e:
            json_response = e.json_response
            if isinstance(json_response, dict) and "error" in json_response:
                error_message = json_response.get("error", {}).get("message") or ""
                helper.raise_broadcast_error(error_message)

            raise e

    def get_prices_per_unit_of_fee(self) -> PricesPerUnit:
        try:
            resp = self.rpc.call("cfx_gasPrice", params=[])
        except JsonRPCException:
            raise FailedToGetGasPrices()

        min_drip: Drip = consts.DEFAULT_GAS_PRICE
        slow = max(_hex2int(resp), min_drip)
        normal = max(round(slow * 1.25), min_drip)
        fast = max(round(slow * 1.5), min_drip)

        return PricesPerUnit(
            normal=EstimatedTimeOnPrice(price=normal, time=60),
            others=[
                EstimatedTimeOnPrice(price=fast, time=30),
                EstimatedTimeOnPrice(price=slow, time=120),
            ],
        )

    def estimate_gas_and_collateral(
        self, from_address: str, to_address: str, value: int, data: str = None
    ) -> Tuple[int, int]:
        resp = self.rpc.call(
            "cfx_estimateGasAndCollateral",
            params=[{"from": from_address, "to": to_address, "value": hex(value), "data": data or "0x"}],
        )
        gas_used = _hex2int(resp.get("gasUsed", "0x0"))
        storage_collateralized = _hex2int(resp.get("storageCollateralized", "0x0"))
        return gas_used, storage_collateralized

    def estimate_gas_limit(self, from_address: str, to_address: str, value: int, data: str = None) -> int:
        gas, _ = self.estimate_gas_and_collateral(from_address, to_address, value, data)
        return gas

    def get_contract_code(self, address: str) -> str:
        try:
            resp = self.rpc.call("cfx_getCode", params=[address, self.EpochTag])
        except JsonRPCException as e:
            # the rpc method cfx_getCode has behavior different from eth
            if "does not exist" in e.message:
                return ""
            else:
                raise e
        else:
            return eth_utils.remove_0x_prefix(resp)

    @functools.lru_cache
    def is_contract(self, address: str) -> bool:
        return len(self.get_contract_code(address)) > 0

    def get_token_info_by_address(self, token_address: str) -> Tuple[str, str, int]:
        # >>> eth_utils.keccak("symbol()".encode())[:4].hex()
        # '95d89b41'
        # >>> eth_utils.keccak("name()".encode())[:4].hex()
        # '06fdde03'
        # >>> eth_utils.keccak("decimals()".encode())[:4].hex()
        # '313ce567'
        symbol_resp, name_resp, decimals_resp = self.call_contract(
            token_address, ["0x95d89b41", "0x06fdde03", "0x313ce567"]
        )
        return (
            _extract_eth_call_str_result(bytes.fromhex(symbol_resp[2:])),
            _extract_eth_call_str_result(bytes.fromhex(name_resp[2:])),
            _hex2int(decimals_resp),
        )

    def get_sponsor_info(self, token_address: str) -> SponsorInfo:
        """Get the sponsor info of the token.
        :param token_address:
        :return:
        """
        res = self.rpc.call("cfx_getSponsorInfo", [token_address])
        sponsor_address_for_storage = res.get("sponsorForCollateral")
        sponsor_address_for_gas = res.get("sponsorForGas")
        sponsor_balance_storage = _hex2int(res.get("sponsorBalanceForCollateral"))
        sponsor_balance_gas = _hex2int(res.get("sponsorBalanceForGas"))
        sponsor_gas_bound = _hex2int(res.get("sponsorGasBound"))
        return SponsorInfo(
            sponsorForCollateral=sponsor_address_for_storage,
            sponsorForGas=sponsor_address_for_gas,
            sponsorBalanceForCollateral=sponsor_balance_storage,
            sponsorBalanceForGas=sponsor_balance_gas,
            sponsorGasBound=sponsor_gas_bound,
        )

    def in_sponsor_whitelist(self, token_address: str, user_address: str, chin_id: str) -> bool:
        """Check if the user_address in the sponsor whitelist of the token.
        :param token_address:
        :param user_address:
        :param chin_id: "1" for test_net "1029" for main_net
        :return:
        """
        # In[15]: eth_utils.keccak("isWhitelisted(address,address)".encode())[:4].hex()
        # Out[15]: 'b6b35272'
        control_contract = consts.SPONSOR_WHITELIST_CONTROL.get(chin_id)
        require_not_none(control_contract, "invalid chain id")
        hex_token_address = cfx_address.Address(base32_address=token_address).hex_address
        hex_user_address = cfx_address.Address(base32_address=user_address).hex_address
        call_data = "0xb6b35272" + eth_abi.encode_abi(["address", "address"], [hex_token_address, hex_user_address])
        res = self.call_contract(control_contract, call_data)
        return eth_abi.decode_single('bool', HexBytes(res))

    def call_contract(self, contract_address: str, data: Union[str, List[str]]) -> Union[str, List[str]]:
        if not self.is_contract(contract_address):
            raise InvalidContractAddress(contract_address)

        if isinstance(data, list):
            return self.rpc.batch_call(
                [("cfx_call", [{"to": contract_address, "data": call_data}, self.EpochTag]) for call_data in data],
                ignore_errors=True,
            )
        else:
            return self.cfx_call({"to": contract_address, "data": data})

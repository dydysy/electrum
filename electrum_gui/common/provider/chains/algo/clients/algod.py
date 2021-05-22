import base64
from typing import List, Optional

from electrum_gui.common.basic.functional.require import require
from electrum_gui.common.basic.functional.text import force_text
from electrum_gui.common.basic.request.exceptions import RequestException, ResponseException
from electrum_gui.common.basic.request.restful import RestfulRequest
from electrum_gui.common.provider import exceptions
from electrum_gui.common.provider.chains.algo.sdk.constants import assettransfer_txn, payment_txn
from electrum_gui.common.provider.chains.algo.sdk.future.transaction import SuggestedParams
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
    TxPaginate,
)
from electrum_gui.common.provider.exceptions import FailedToGetSuggestedParams, TransactionNotFound
from electrum_gui.common.provider.interfaces import ClientInterface, SearchTransactionMixin


def _parse_transactions(tx: dict) -> Transaction:
    """Parse transaction from raw rpc response
    :param tx:
    :return:
    """
    block_header = BlockHeader(
        block_hash=tx.get("blockHash", ""),  # can't get
        block_number=tx.get("confirmed-round", 0),
        block_time=tx.get("round-time", 0),
    )
    status = TransactionStatus.CONFIRM_SUCCESS

    fee = TransactionFee(
        limit=tx.get("fee"),
        used=tx.get("fee"),
        price_per_unit=1,  # maintain internal consistency
    )
    tx_type = tx["tx-type"]
    sender = tx.get("sender", "")
    receiver = ""
    value = 0
    token_address = None
    if tx_type == payment_txn:
        receiver = tx["payment-transaction"].get("receiver", "")
        value = tx["payment-transaction"].get("amount", 0)
    elif tx_type == assettransfer_txn:
        token_address = str(tx["asset-transfer-transaction"]["asset-id"])
        receiver = tx["asset-transfer-transaction"].get("receiver", "")
        value = tx["asset-transfer-transaction"].get("amount", 0)

    return Transaction(
        txid=tx.get("id"),
        inputs=[TransactionInput(address=sender, token_address=token_address, value=value)],
        outputs=[TransactionOutput(address=receiver, token_address=token_address, value=value)],
        status=status,
        block_header=block_header,
        fee=fee,
        nonce=0,
    )


class ALGORestful(ClientInterface, SearchTransactionMixin):
    def __init__(self, url: str, api_keys: List[str] = None):
        self.restful = RestfulRequest(
            url,
            timeout=10,
            session_initializer=lambda s: s.headers.update({"x-api-key": api_keys[0]}) if api_keys else None,
        )

    def get_info(self) -> ClientInfo:
        resp = self.restful.get("/ps2/v2/status")

        is_ready = resp.get("catchup-time", 1) == 0
        if is_ready:
            time_since_last_round = resp.get("time-since-last-round")
            is_ready = time_since_last_round < 1e9 * 60  # 1 min

        return ClientInfo(
            name="algod",
            best_block_number=resp.get("last-round", 0),
            is_ready=is_ready,
            desc="",
        )

    def get_address(self, address: str) -> Address:
        resp = self._get_raw_address_info(address)

        return Address(
            address=address,
            balance=resp["amount"],
            existing=bool(resp["amount"]) or bool(resp["assets"]),
        )

    def _get_raw_address_info(self, address: str) -> dict:
        resp = self.restful.get(f"/ps2/v2/accounts/{address}")
        require(resp["address"] == address)
        return resp

    def get_balance(self, address: str, token_address: Optional[str] = None) -> int:
        if token_address is None:
            return super(ALGORestful, self).get_balance(address)
        else:
            resp = self._get_raw_address_info(address)
            for token_dict in resp.get("assets") or ():
                if token_dict.get("asset-id") == int(token_address):
                    return token_dict.get("amount", 0)
            return 0

    def get_transaction_by_txid(self, txid: str) -> Transaction:
        try:
            # todo handle pending tx
            # pending = self.restful.get(f"/ps2/v2/transactions/pending/{txid}")
            resp = self.restful.get(f"/idx2/v2/transactions/{txid}")
        except ResponseException as e:
            if e.response is not None and "no transaction found" in force_text(e.response.text):
                raise TransactionNotFound(txid)
            else:
                raise e

        return _parse_transactions(resp.get("transaction"))

    def search_txs_by_address(self, address: str, paginate: Optional[TxPaginate] = None) -> List[Transaction]:
        """Retrieve the latest 50 transactions."""
        if paginate:
            # TODO: paginate
            pass
        resp = self.restful.get(f"/idx2/v2/accounts/{address}/transactions", params={"limit": 50})
        return [_parse_transactions(tx) for tx in resp.get("transactions", [])]

    def broadcast_transaction(self, raw_tx: str) -> TxBroadcastReceipt:
        try:
            resp = self.restful.post(
                "/ps2/v2/transactions", data=base64.b64decode(raw_tx), headers={'Content-Type': 'application/x-binary'}
            )
        except ResponseException as e:
            try:
                resp = e.response.json()
            except ValueError:
                resp = dict()

        txid = resp.get("txId")
        if txid:
            return TxBroadcastReceipt(is_success=True, receipt_code=TxBroadcastReceiptCode.SUCCESS, txid=txid)
        else:
            raise exceptions.UnknownBroadcastError("malformed algorand transaction" if resp.status_code == 400 else "")

    def get_prices_per_unit_of_fee(self) -> PricesPerUnit:
        normal = EstimatedTimeOnPrice(price=1, time=15)  # maintain internal consistency
        return PricesPerUnit(normal=normal)

    def get_suggested_params(self) -> SuggestedParams:
        try:
            resp = self.restful.get("/ps2/v2/transactions/params")
        except RequestException:
            raise FailedToGetSuggestedParams()

        return SuggestedParams(
            resp["fee"],
            resp["last-round"],
            resp["last-round"] + 1000,
            resp["genesis-hash"],
            resp["genesis-id"],
            False,
            resp["consensus-version"],
            resp["min-fee"],
        )

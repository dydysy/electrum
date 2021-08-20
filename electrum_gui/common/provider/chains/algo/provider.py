import base64
from typing import Dict, Tuple

from electrum_gui.common.basic.functional.require import require
from electrum_gui.common.provider.chains.algo import ALGORestful
from electrum_gui.common.provider.chains.algo import sdk as algo_sdk
from electrum_gui.common.provider.chains.algo.sdk.future.transaction import (
    AssetTransferTxn,
    PaymentTxn,
    SignedTransaction,
)
from electrum_gui.common.provider.data import AddressValidation, SignedTx, UnsignedTx
from electrum_gui.common.provider.interfaces import ProviderInterface
from electrum_gui.common.secret.interfaces import SignerInterface, VerifierInterface


class ALGOProvider(ProviderInterface):
    def verify_address(self, address: str) -> AddressValidation:
        _normalized_address, _display_address, _encoding = "", "", None
        is_valid = algo_sdk.encoding.is_valid_address(address)
        if is_valid:
            _normalized_address, _display_address, _encoding = address, address, "BASE32"
        return AddressValidation(
            normalized_address=_normalized_address,
            display_address=_display_address,
            is_valid=is_valid,
            encoding=_encoding,
        )

    def pubkey_to_address(self, verifier: VerifierInterface, encoding: str = "BASE32") -> str:
        require(encoding == "BASE32")
        pubkey = verifier.get_pubkey(compressed=False)
        address = algo_sdk.encoding.encode_address(pubkey)
        return address

    @property
    def client(self) -> ALGORestful:
        return self.client_selector(instance_required=ALGORestful)

    def fill_unsigned_tx(self, unsigned_tx: UnsignedTx) -> UnsignedTx:
        tx_params = self.client.get_suggested_params()
        payload = unsigned_tx.payload.copy()
        tx_input = unsigned_tx.inputs[0] if unsigned_tx.inputs else None
        tx_output = unsigned_tx.outputs[0] if unsigned_tx.outputs else None
        fee_limit = unsigned_tx.fee_limit  # fee_limit: special treatment for algo, fee_limit is final cost fee

        if fee_limit:
            tx_params.flat_fee = True
            tx_params.fee = fee_limit

        pay_tx = None
        if tx_input is not None and tx_output is not None:
            from_address = tx_input.address
            to_address = tx_output.address
            token_address = tx_output.token_address
            value = tx_output.value
            if token_address is None:
                pay_tx = PaymentTxn(from_address, tx_params, to_address, value)
            else:
                pay_tx = AssetTransferTxn(from_address, tx_params, to_address, value, int(token_address))
            payload["txScript"] = pay_tx

        return unsigned_tx.clone(
            inputs=[tx_input] if tx_input is not None else [],
            outputs=[tx_output] if tx_output is not None else [],
            fee_limit=pay_tx.fee if pay_tx is not None else algo_sdk.constants.min_txn_fee,
            fee_price_per_unit=1,  # maintain internal consistency
            payload=payload,
        )

    def sign_transaction(self, unsigned_tx: UnsignedTx, signers: Dict[str, SignerInterface]) -> SignedTx:
        require(len(unsigned_tx.inputs) == 1 and len(unsigned_tx.outputs) == 1)
        from_address = unsigned_tx.inputs[0].address
        signer = signers.get(from_address)
        require(signer is not None)
        require(unsigned_tx.payload.get("txScript") is not None)

        txn = algo_sdk.encoding.msgpack_encode(unsigned_tx.payload["txScript"])
        signature, _ = signer.sign(algo_sdk.constants.txid_prefix + base64.b64decode(txn))
        signature = base64.b64encode(signature).decode()
        stx = SignedTransaction(unsigned_tx.payload["txScript"], signature, None)

        return SignedTx(
            txid=stx.get_txid(),
            raw_tx=algo_sdk.encoding.msgpack_encode(stx),
        )

    def get_token_info_by_address(self, token_address: str) -> Tuple[str, str, int]:
        raise NotImplementedError()

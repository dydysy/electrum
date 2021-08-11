from typing import Dict, Tuple

import eth_abi
import eth_utils

from electrum_gui.common.basic.functional.require import require
from electrum_gui.common.provider.chains.cfx.conflux import CFXClient
from electrum_gui.common.provider.chains.cfx.sdk import cfx_account
from electrum_gui.common.provider.chains.cfx.sdk.cfx_address import Address
from electrum_gui.common.provider.chains.cfx.sdk.cfx_address import utils as cfx_utils
from electrum_gui.common.provider.chains.eth.message_mixin import ETHMessageMixin
from electrum_gui.common.provider.chains.eth.provider import _EthKey
from electrum_gui.common.provider.data import AddressValidation, SignedTx, UnsignedTx
from electrum_gui.common.provider.interfaces import ProviderInterface
from electrum_gui.common.secret.interfaces import SignerInterface, VerifierInterface


class CFXProvider(ProviderInterface, ETHMessageMixin):
    @property
    def client(self) -> CFXClient:
        return self.client_selector(instance_required=CFXClient)

    def verify_address(self, address: str) -> AddressValidation:
        is_valid = Address.is_valid_base32(address)
        normalized_address, display_address = (address.lower(), address.lower()) if is_valid else ("", "")
        return AddressValidation(
            normalized_address=normalized_address,
            display_address=display_address,
            is_valid=is_valid,
        )

    def pubkey_to_address(self, verifier: VerifierInterface, encoding: str = None) -> str:
        pubkey = verifier.get_pubkey(compressed=False)
        address = Address.encode_hex_address(
            cfx_utils.eth_address_to_cfx(eth_utils.keccak(pubkey[1:])[-20:].hex()), int(self.chain_info.chain_id)
        )  # noqa
        return address

    def fill_unsigned_tx(self, unsigned_tx: UnsignedTx) -> UnsignedTx:
        fee_price_per_unit = unsigned_tx.fee_price_per_unit or self.client.get_prices_per_unit_of_fee().normal.price
        nonce = unsigned_tx.nonce
        payload = unsigned_tx.payload.copy()
        tx_input = unsigned_tx.inputs[0] if unsigned_tx.inputs else None
        tx_output = unsigned_tx.outputs[0] if unsigned_tx.outputs else None
        fee_limit = unsigned_tx.fee_limit

        if tx_input is not None and tx_output is not None:
            from_address = tx_input.address
            to_address = tx_output.address
            value = tx_output.value
            token_address = tx_output.token_address

            if nonce is None:
                nonce = self.client.get_address(from_address).nonce

            if token_address is None:
                data = payload.get("data")
            else:
                to_address = Address.decode_hex_address(to_address)
                data = eth_utils.add_0x_prefix(
                    "a9059cbb" + eth_abi.encode_abi(("address", "uint256"), (to_address, value)).hex()
                )  # method_selector(transfer) + byte32_pad(address) + byte32_pad(value)
                value = 0
                to_address = token_address

            if data:
                payload["data"] = data

            if not fee_limit:
                estimate_fee_limit = self.client.estimate_gas_limit(from_address, to_address, value, data)
                fee_limit = (
                    round(estimate_fee_limit * 1.2)
                    if token_address or self.client.is_contract(to_address)
                    else estimate_fee_limit
                )
            _, storage_limit = self.client.estimate_gas_and_collateral(from_address, to_address, value, data)
            epoch_height = self.client.get_epoch_number()
            payload["storage_limit"] = storage_limit
            payload["epoch_height"] = epoch_height

        fee_limit = fee_limit or 21000

        return unsigned_tx.clone(
            inputs=[tx_input] if tx_input is not None else [],
            outputs=[tx_output] if tx_output is not None else [],
            fee_limit=fee_limit,
            fee_price_per_unit=fee_price_per_unit,
            nonce=nonce,
            payload=payload,
        )

    def sign_transaction(self, unsigned_tx: UnsignedTx, signers: Dict[str, SignerInterface]) -> SignedTx:
        # TODO: check whether main coin balance and token balance are enough
        # balance >= value + gas * gasPrice + storage_limit * (10^18/1024)
        require(len(unsigned_tx.inputs) == 1 and len(unsigned_tx.outputs) == 1)
        from_address = unsigned_tx.inputs[0].address
        require(signers.get(from_address) is not None)

        cfx_key = _EthKey(signers[from_address])

        output = unsigned_tx.outputs[0]
        is_erc20_transfer = bool(output.token_address)
        to_address = output.token_address if is_erc20_transfer else output.address
        value = 0 if is_erc20_transfer else output.value
        tx_dict = {
            "to": to_address,
            "value": value,
            "gas": unsigned_tx.fee_limit,
            "gasPrice": unsigned_tx.fee_price_per_unit,
            "storageLimit": unsigned_tx.payload.get("storage_limit"),
            "epochHeight": unsigned_tx.payload.get("epoch_height"),
            "nonce": unsigned_tx.nonce,
            "data": eth_utils.add_0x_prefix(unsigned_tx.payload.get("data") or "0x"),
            "chainId": int(self.chain_info.chain_id),
        }

        _, _, _, encoded_tx = cfx_account.signing.sign_transaction_dict(cfx_key, tx_dict)
        return SignedTx(
            txid=eth_utils.add_0x_prefix(eth_utils.keccak(encoded_tx).hex()),  # noqa
            raw_tx=eth_utils.add_0x_prefix(encoded_tx.hex()),
        )

    def get_token_info_by_address(self, token_address: str) -> Tuple[str, str, int]:
        return self.client.get_token_info_by_address(token_address)

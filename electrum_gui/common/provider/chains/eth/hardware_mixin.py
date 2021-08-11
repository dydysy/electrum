import abc
import logging
from typing import Dict

from eth_account._utils import transactions as eth_account_transactions  # noqa
from trezorlib import ethereum as trezor_ethereum

from electrum_gui.common.basic import bip44
from electrum_gui.common.basic.functional.require import require
from electrum_gui.common.hardware import interfaces as hardware_interfaces
from electrum_gui.common.provider import data, interfaces
from electrum_gui.common.provider.chains.eth.sdk import message as message_sdk
from electrum_gui.common.provider.chains.eth.sdk import utils

logger = logging.getLogger("app.chain")


def _verify_message_for_hardware(message):
    if utils.is_hexstr(message):
        logger.warning(
            "This device will treat this message as a personal message. "
            "Maybe you want to use this message as a message hash?"
        )
    else:
        require(not message_sdk.is_typed_data_message(message), "Not supported on this device")


class ETHHardwareMixin(interfaces.HardwareSupportingMixin, abc.ABC):
    @abc.abstractmethod
    def verify_address(self, address: str) -> data.AddressValidation:
        pass

    @abc.abstractmethod
    def _build_unsigned_tx_dict(self, unsigned_tx: data.UnsignedTx) -> dict:
        pass

    def hardware_get_xpub(
        self,
        hardware_client: hardware_interfaces.HardwareClientInterface,
        bip44_path: bip44.BIP44Path,
        confirm_on_device: bool = False,
    ) -> str:
        return trezor_ethereum.get_public_node(
            hardware_client, n=bip44_path.to_bip44_int_path(), show_display=confirm_on_device
        ).xpub

    def hardware_get_address(
        self,
        hardware_client: hardware_interfaces.HardwareClientInterface,
        bip44_path: bip44.BIP44Path,
        confirm_on_device: bool = False,
    ) -> str:
        address = trezor_ethereum.get_address(
            hardware_client, n=bip44_path.to_bip44_int_path(), show_display=confirm_on_device
        )
        return self.verify_address(address).normalized_address

    def hardware_sign_transaction(
        self,
        hardware_client: hardware_interfaces.HardwareClientInterface,
        unsigned_tx: data.UnsignedTx,
        bip44_path_of_signers: Dict[str, bip44.BIP44Path],
    ) -> data.SignedTx:
        require(len(unsigned_tx.inputs) == 1 and len(unsigned_tx.outputs) == 1)
        from_address = unsigned_tx.inputs[0].address
        require(bip44_path_of_signers.get(from_address) is not None)

        tx_dict = self._build_unsigned_tx_dict(unsigned_tx)
        v, r, s = trezor_ethereum.sign_tx(
            hardware_client,
            n=bip44_path_of_signers[from_address].to_bip44_int_path(),
            nonce=tx_dict["nonce"],
            gas_price=tx_dict["gasPrice"],
            gas_limit=tx_dict["gas"],
            to=tx_dict["to"],
            value=tx_dict["value"],
            data=bytes.fromhex(utils.remove_0x_prefix(tx_dict["data"])) if tx_dict.get("data") else None,
            chain_id=tx_dict["chainId"],
        )
        encoded_tx = eth_account_transactions.encode_transaction(
            eth_account_transactions.serializable_unsigned_transaction_from_dict(tx_dict),
            (v, utils.big_endian_to_int(r), utils.big_endian_to_int(s)),
        )

        return data.SignedTx(
            txid=utils.add_0x_prefix(utils.keccak(encoded_tx).hex()),
            raw_tx=utils.add_0x_prefix(encoded_tx.hex()),
        )

    def hardware_sign_message(
        self,
        hardware_client: hardware_interfaces.HardwareClientInterface,
        message: str,
        signer_bip44_path: bip44.BIP44Path,
    ) -> str:
        _verify_message_for_hardware(message)
        return utils.add_0x_prefix(
            trezor_ethereum.sign_message(
                hardware_client,
                n=signer_bip44_path.to_bip44_int_path(),
                message=message,
            ).signature.hex()
        )

    def hardware_verify_message(
        self,
        hardware_client: hardware_interfaces.HardwareClientInterface,
        address: str,
        message: str,
        signature: str,
    ) -> bool:
        _verify_message_for_hardware(message)
        signature = bytes.fromhex(utils.remove_0x_prefix(signature))

        return trezor_ethereum.verify_message(
            hardware_client,
            address=address,
            message=message,
            signature=signature,
        )

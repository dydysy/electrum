import abc

import eth_utils

from electrum_gui.common.provider import interfaces
from electrum_gui.common.provider.chains.eth.sdk import message as message_sdk
from electrum_gui.common.provider.chains.eth.sdk import utils
from electrum_gui.common.secret import data as secret_data
from electrum_gui.common.secret import interfaces as secret_interfaces
from electrum_gui.common.secret.keys.base import BaseECDSAKey
from electrum_gui.common.secret.registry import key_class_on_curve


class ETHMessageMixin(interfaces.MessageSupportingMixin, abc.ABC):
    @abc.abstractmethod
    def pubkey_to_address(self, verifier: secret_interfaces.VerifierInterface, encoding: str = None) -> str:
        pass

    def sign_message(self, message: str, signer: secret_interfaces.SignerInterface) -> str:
        message_hash = message_sdk.hash_message(message)
        sig, rec_id = signer.sign(message_hash)
        v = rec_id + 27
        sig += bytes([v])
        return utils.add_0x_prefix(sig.hex())

    def verify_message(self, address: str, message: str, signature: str) -> bool:
        recovered_address = self.ec_recover(message, signature)
        return recovered_address == address

    def ec_recover(self, message: str, signature: str) -> str:
        message_hash = message_sdk.hash_message(message)
        signature = bytes.fromhex(utils.remove_0x_prefix(signature))
        r, s, v = signature[:32], signature[32:64], signature[64]

        curve_cls = key_class_on_curve(secret_data.CurveEnum.SECP256K1)
        assert issubclass(curve_cls, BaseECDSAKey)

        pubkey = curve_cls.recover_public_key(
            eth_utils.big_endian_to_int(message_hash),
            eth_utils.big_endian_to_int(r),
            eth_utils.big_endian_to_int(s),
            v - 27,
        )
        verifier = curve_cls.from_key(pubkey=pubkey)
        return self.pubkey_to_address(verifier)

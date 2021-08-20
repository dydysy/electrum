import base64
from collections import OrderedDict

from electrum_gui.common.provider.chains.algo.sdk import constants, encoding, error

SIG_PLACEHOLDER = base64.b64encode(bytes(64)).decode()


class SuggestedParams:
    """
    Contains various fields common to all transaction types.

    Args:
        fee (int): transaction fee (per byte if flat_fee is false). When flat_fee is true,
            fee may fall to zero but a group of N atomic transactions must
            still have a fee of at least N*min_txn_fee.
        first (int): first round for which the transaction is valid
        last (int): last round for which the transaction is valid
        gh (str): genesis hash
        gen (str, optional): genesis id
        flat_fee (bool, optional): whether the specified fee is a flat fee
        consensus_version (str, optional): the consensus protocol version as of 'first'
        min_fee (int, optional): the minimum transaction fee (flat)

    Attributes:
        fee (int)
        first (int)
        last (int)
        gen (str)
        gh (str)
        flat_fee (bool)
        consensus_version (str)
        min_fee (int)
    """

    def __init__(self, fee, first, last, gh, gen=None, flat_fee=False, consensus_version=None, min_fee=None):
        self.first = first
        self.last = last
        self.gh = gh
        self.gen = gen
        self.fee = fee
        self.flat_fee = flat_fee
        self.consensus_version = consensus_version
        self.min_fee = min_fee


class Transaction:
    """
    Superclass for various transaction types.
    """

    def __init__(self, sender, sp, note, lease, txn_type, rekey_to):
        self.sender = sender
        self.fee = sp.fee
        self.first_valid_round = sp.first
        self.last_valid_round = sp.last
        self.note = self.as_note(note)
        self.genesis_id = sp.gen
        self.genesis_hash = sp.gh
        self.group = None
        self.lease = self.as_lease(lease)
        self.type = txn_type
        self.rekey_to = rekey_to

    @staticmethod
    def as_hash(hash):
        """Confirm that a value is 32 bytes. If all zeros, or a falsy value, return None"""
        if not hash:
            return None
        assert isinstance(hash, (bytes, bytearray)), "{} is not bytes".format(hash)
        if len(hash) != constants.hash_len:
            raise error.WrongHashLengthError
        if not any(hash):
            return None
        return hash

    @staticmethod
    def as_note(note):
        if not note:
            return None
        if not isinstance(note, (bytes, bytearray, str)):
            raise error.WrongNoteType
        if isinstance(note, str):
            note = note.encode()
        if len(note) > constants.note_max_length:
            raise error.WrongNoteLength
        return note

    @classmethod
    def as_lease(cls, lease):
        try:
            return cls.as_hash(lease)
        except error.WrongHashLengthError:
            raise error.WrongLeaseLengthError

    def get_txid(self):
        """
        Get the transaction's ID.

        Returns:
            str: transaction ID
        """
        txn = encoding.msgpack_encode(self)
        to_sign = constants.txid_prefix + base64.b64decode(txn)
        txid = encoding.checksum(to_sign)
        txid = base64.b32encode(txid).decode()
        return encoding.undo_padding(txid)

    def estimate_size(self):
        stx = SignedTransaction(self, SIG_PLACEHOLDER)
        return len(base64.b64decode(encoding.msgpack_encode(stx)))

    def dictify(self):
        d = dict()
        if self.fee:
            d["fee"] = self.fee
        if self.first_valid_round:
            d["fv"] = self.first_valid_round
        if self.genesis_id:
            d["gen"] = self.genesis_id
        d["gh"] = base64.b64decode(self.genesis_hash)
        if self.group:
            d["grp"] = self.group
        d["lv"] = self.last_valid_round
        if self.lease:
            d["lx"] = self.lease
        if self.note:
            d["note"] = self.note
        d["snd"] = encoding.decode_address(self.sender)
        d["type"] = self.type
        if self.rekey_to:
            d["rekey"] = encoding.decode_address(self.rekey_to)

        return d

    @staticmethod
    def undictify(d):
        sp = SuggestedParams(
            d["fee"] if "fee" in d else 0,
            d["fv"] if "fv" in d else 0,
            d["lv"],
            base64.b64encode(d["gh"]).decode(),
            d["gen"] if "gen" in d else None,
            flat_fee=True,
        )
        args = {
            "sp": sp,
            "sender": encoding.encode_address(d["snd"]),
            "note": d["note"] if "note" in d else None,
            "lease": d["lx"] if "lx" in d else None,
            "rekey_to": encoding.encode_address(d["rekey"]) if "rekey" in d else None,
        }
        txn_type = d["type"]
        if not isinstance(d["type"], str):
            txn_type = txn_type.decode()
        if txn_type == constants.payment_txn:
            args.update(PaymentTxn._undictify(d))
            txn = PaymentTxn(**args)
        elif txn_type == constants.assettransfer_txn:
            args.update(AssetTransferTxn._undictify(d))
            txn = AssetTransferTxn(**args)
        if "grp" in d:
            txn.group = d["grp"]
        return txn

    @staticmethod
    def creatable_index(index, required=False):
        """Coerce an index for apps or assets to an integer.

        By using this in all constructors, we allow callers to use
        strings as indexes, check our convenience Txn types to ensure
        index is set, and ensure that 0 is always used internally for
        an unset id, not None, so __eq__ works properly.
        """
        i = int(index or 0)
        if i == 0 and required:
            raise IndexError("Required an index")
        if i < 0:
            raise IndexError(i)
        return i

    def __str__(self):
        return str(self.__dict__)


class PaymentTxn(Transaction):
    """
    Represents a payment transaction.

    Args:
        sender (str): address of the sender
        sp (SuggestedParams): suggested params from algod
        receiver (str): address of the receiver
        amt (int): amount in microAlgos to be sent
        close_remainder_to (str, optional): if nonempty, account will be closed
            and remaining algos will be sent to this address
        note (bytes, optional): arbitrary optional bytes
        lease (byte[32], optional): specifies a lease, and no other transaction
            with the same sender and lease can be confirmed in this
            transaction's valid rounds
        rekey_to (str, optional): additionally rekey the sender to this address

    Attributes:
        sender (str)
        fee (int)
        first_valid_round (int)
        last_valid_round (int)
        note (bytes)
        genesis_id (str)
        genesis_hash (str)
        group (bytes)
        receiver (str)
        amt (int)
        close_remainder_to (str)
        type (str)
        lease (byte[32])
        rekey_to (str)
    """

    def __init__(self, sender, sp, receiver, amt, close_remainder_to=None, note=None, lease=None, rekey_to=None):
        Transaction.__init__(self, sender, sp, note, lease, constants.payment_txn, rekey_to)
        if receiver:
            self.receiver = receiver
        else:
            raise error.ZeroAddressError

        self.amt = amt
        if (not isinstance(self.amt, int)) or self.amt < 0:
            raise error.WrongAmountType
        self.close_remainder_to = close_remainder_to
        if not sp.flat_fee:
            self.fee = max(self.estimate_size() * self.fee, constants.min_txn_fee)

    def dictify(self):
        d = dict()
        if self.amt:
            d["amt"] = self.amt
        if self.close_remainder_to:
            d["close"] = encoding.decode_address(self.close_remainder_to)

        decoded_receiver = encoding.decode_address(self.receiver)
        if any(decoded_receiver):
            d["rcv"] = encoding.decode_address(self.receiver)

        d.update(super(PaymentTxn, self).dictify())
        od = OrderedDict(sorted(d.items()))

        return od

    @staticmethod
    def _undictify(d):
        args = {
            "close_remainder_to": encoding.encode_address(d["close"]) if "close" in d else None,
            "amt": d["amt"] if "amt" in d else 0,
            "receiver": encoding.encode_address(d["rcv"]) if "rcv" in d else None,
        }
        return args


class AssetTransferTxn(Transaction):
    """
    Represents a transaction for asset transfer.

    To begin accepting an asset, supply the same address as both sender and
    receiver, and set amount to 0 (or use AssetOptInTxn)

    To revoke an asset, set revocation_target, and issue the transaction from
    the asset's revocation manager account.

    Args:
        sender (str): address of the sender
        sp (SuggestedParams): suggested params from algod
        receiver (str): address of the receiver
        amt (int): amount of asset base units to send
        index (int): index of the asset
        close_assets_to (string, optional): send all of sender's remaining
            assets, after paying `amt` to receiver, to this address
        revocation_target (string, optional): send assets from this address,
            rather than the sender's address (can only be used by an asset's
            revocation manager, also known as clawback)
        note (bytes, optional): arbitrary optional bytes
        lease (byte[32], optional): specifies a lease, and no other transaction
            with the same sender and lease can be confirmed in this
            transaction's valid rounds
        rekey_to (str, optional): additionally rekey the sender to this address

    Attributes:
        sender (str)
        fee (int)
        first_valid_round (int)
        last_valid_round (int)
        genesis_hash (str)
        index (int)
        amount (int)
        receiver (string)
        close_assets_to (string)
        revocation_target (string)
        note (bytes)
        genesis_id (str)
        type (str)
        lease (byte[32])
        rekey_to (str)
    """

    def __init__(
        self,
        sender,
        sp,
        receiver,
        amt,
        index,
        close_assets_to=None,
        revocation_target=None,
        note=None,
        lease=None,
        rekey_to=None,
    ):
        Transaction.__init__(self, sender, sp, note, lease, constants.assettransfer_txn, rekey_to)
        if receiver:
            self.receiver = receiver
        else:
            raise error.ZeroAddressError
        self.amount = amt
        if (not isinstance(self.amount, int)) or self.amount < 0:
            raise error.WrongAmountType
        self.index = self.creatable_index(index, required=True)
        self.close_assets_to = close_assets_to
        self.revocation_target = revocation_target
        if not sp.flat_fee:
            self.fee = max(self.estimate_size() * self.fee, constants.min_txn_fee)

    def dictify(self):
        d = dict()

        if self.amount:
            d["aamt"] = self.amount
        if self.close_assets_to:
            d["aclose"] = encoding.decode_address(self.close_assets_to)

        decoded_receiver = encoding.decode_address(self.receiver)
        if any(decoded_receiver):
            d["arcv"] = encoding.decode_address(self.receiver)
        if self.revocation_target:
            d["asnd"] = encoding.decode_address(self.revocation_target)

        if self.index:
            d["xaid"] = self.index

        d.update(super(AssetTransferTxn, self).dictify())
        od = OrderedDict(sorted(d.items()))

        return od

    @staticmethod
    def _undictify(d):
        args = {
            "receiver": encoding.encode_address(d["arcv"]) if "arcv" in d else None,
            "amt": d["aamt"] if "aamt" in d else 0,
            "index": d["xaid"] if "xaid" in d else None,
            "close_assets_to": encoding.encode_address(d["aclose"]) if "aclose" in d else None,
            "revocation_target": encoding.encode_address(d["asnd"]) if "asnd" in d else None,
        }

        return args


class SignedTransaction:
    """
    Represents a signed transaction.

    Args:
        transaction (Transaction): transaction that was signed
        signature (str): signature of a single address
        authorizing_address (str, optional): the address authorizing the signed transaction, if different from sender

    Attributes:
        transaction (Transaction)
        signature (str)
        authorizing_address (str)
    """

    def __init__(self, transaction, signature, authorizing_address=None):
        self.signature = signature
        self.transaction = transaction
        self.authorizing_address = authorizing_address

    def get_txid(self):
        """
        Get the transaction's ID.

        Returns:
            str: transaction ID
        """
        return self.transaction.get_txid()

    def dictify(self):
        od = OrderedDict()
        if self.signature:
            od["sig"] = base64.b64decode(self.signature)
        od["txn"] = self.transaction.dictify()
        if self.authorizing_address:
            od["sgnr"] = encoding.decode_address(self.authorizing_address)
        return od

    @staticmethod
    def undictify(d):
        sig = None
        if "sig" in d:
            sig = base64.b64encode(d["sig"]).decode()
        auth = None
        if "sgnr" in d:
            auth = encoding.encode_address(d["sgnr"])
        txn = Transaction.undictify(d["txn"])
        stx = SignedTransaction(txn, sig, auth)
        return stx

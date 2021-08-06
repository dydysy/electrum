import json
from typing import Any, Callable, Iterable, Sequence, Tuple

import eth_abi
from eth_account._utils.structured_data.hashing import encode_type as encode_primary_type

from electrum_gui.common.basic.functional.require import require
from electrum_gui.common.provider.chains.eth.sdk import solidity, utils

_LEGACY_EIP712_ITEM_FIELD_NAMES = {"type", "name", "value"}  # V1
_STANDARD_EIP712_FIELD_NAMES = {"types", "primaryType", "domain", "message"}  # V3 and V4


def _to_buffer(value: str) -> bytes:
    if value.startswith("0x") and utils.is_hexstr(value):
        value = utils.remove_0x_prefix(value)
        if len(value) & 1 == 1:
            value = "0" + value  # pad to even

        return utils.decode_hex(value)
    else:
        return value.encode()


def _hash_personal_message(message: str) -> bytes:
    message_bytes = _to_buffer(message)
    preamble = f"\x19Ethereum Signed Message:\n{len(message_bytes)}"
    message_bytes = preamble.encode() + message_bytes

    return utils.keccak(message_bytes)


def _hash_legacy_typed_data_message(data: list) -> bytes:
    values, types, schemas = [], [], []

    for item in data:
        solidity_type, name, value = item["type"], item["name"], item["value"]
        require(name)

        values.append(value)
        types.append(solidity_type)
        schemas.append(f"{solidity_type} {name}")

    return solidity.solidity_sha3(
        ('bytes32', 'bytes32'),
        (
            solidity.solidity_sha3(["string"] * len(data), schemas),
            solidity.solidity_sha3(types, values),
        ),
    )


def _encode_and_hash_data(primary_type: str, data: dict, types: dict, type_value_pair_generator: Callable) -> bytes:
    data_types, data_values = zip(*type_value_pair_generator(primary_type, data, types))
    return utils.keccak(eth_abi.encode_abi(data_types, data_values))


def _normalized_value(field_type: str, value: Any) -> Any:
    if not field_type or not value:
        return value

    if field_type.startswith("bytes") and isinstance(value, str):
        value = bytes.fromhex(utils.remove_0x_prefix(value))
    elif (field_type.startswith("int") or field_type.startswith("uint")) and isinstance(value, str):
        value = int(value, base=16 if value.startswith("0x") else 10)

    return value


def _generate_v3_type_value_pair(primary_type: str, data: dict, types: dict) -> Iterable[Tuple[str, Any]]:
    yield "bytes32", utils.keccak(text=encode_primary_type(primary_type, types))

    for field in types[primary_type]:
        field_name, field_type = field.get("name"), field.get("type")
        value = data.get(field_name)
        value = _normalized_value(field_type, value)

        if value is None:
            continue
        elif solidity.is_array_type(field_type):
            raise Exception("Arrays are unimplemented in V3, use V4 extension")
        elif types.get(field_type) is not None:
            yield "bytes32", _encode_and_hash_data(field_type, value, types, _generate_v3_type_value_pair)
        elif field_type in ("bytes", "string"):
            value = utils.keccak(solidity.solidity_encode_value(field_type, value))
            yield "bytes32", value
        else:
            yield field_type, value


def _generate_v4_type_value_pair(primary_type: str, data: dict, types: dict) -> Iterable[Tuple[str, Any]]:
    yield "bytes32", utils.keccak(text=encode_primary_type(primary_type, types))

    def _encode_field(field_name: str, field_type: str, value: Any) -> Tuple[str, Any]:
        value = _normalized_value(field_type, value)

        if types.get(field_type) is not None:
            return "bytes32", (
                bytes(32)
                if value is None
                else _encode_and_hash_data(field_type, value, types, _generate_v4_type_value_pair)
            )
        elif value is None:
            raise Exception(f"Missing value for field {field_name} of type {field_type}")
        elif solidity.is_array_type(field_type):
            require(isinstance(value, Sequence), f"Invalid {field_type}: {repr(value)}")
            sub_type = solidity.parse_sub_type_of_array_type(field_type)
            sub_types, sub_values = zip(*(_encode_field(field_name, sub_type, i) for i in value))
            return "bytes32", utils.keccak(eth_abi.encode_abi(sub_types, sub_values))
        elif field_type in ("bytes", "string"):
            value = utils.keccak(solidity.solidity_encode_value(field_type, value))
            return "bytes32", value
        else:
            return field_type, value

    for field in types[primary_type]:
        yield _encode_field(field.get("name"), field.get("type"), data.get(field.get("name")))


def _hash_standard_typed_data_message(data: dict, type_value_pair_generator: Callable) -> bytes:
    buffer = bytearray()
    buffer.extend(b"\x19\x01")
    buffer.extend(_encode_and_hash_data("EIP712Domain", data["domain"], data["types"], type_value_pair_generator))

    if data["primaryType"] != "EIP712Domain":
        buffer.extend(
            _encode_and_hash_data(data["primaryType"], data["message"], data["types"], type_value_pair_generator)
        )

    return utils.keccak(buffer)


def _hash_typed_data_message(message: str) -> bytes:
    data = json.loads(message)

    if isinstance(data, list):
        return _hash_legacy_typed_data_message(data)
    elif isinstance(data, dict):
        version = data.pop("__version__", 4)  # Non-standard field
        if version == 3:
            return _hash_standard_typed_data_message(data, _generate_v3_type_value_pair)
        elif version == 4:
            return _hash_standard_typed_data_message(data, _generate_v4_type_value_pair)

    raise Exception(f"Invalid typed data message. message: {message}")


def is_typed_data_message(message: str) -> int:
    try:
        data = json.loads(message)
    except ValueError:
        return False

    if not data:
        return False
    elif isinstance(data, list):  # V1?
        return all(isinstance(item, dict) and _LEGACY_EIP712_ITEM_FIELD_NAMES.issubset(item.keys()) for item in data)
    elif isinstance(data, dict):  # V3 or V4?
        return _STANDARD_EIP712_FIELD_NAMES.issubset(data.keys())

    return False


def hash_message(message: str) -> bytes:
    try:
        if (
            message.startswith("0x") and len(message) == 66 and utils.is_hexstr(message)
        ):  # Only a hexadecimal string starting with 0x and having a length of 66, that is, 64 bytes
            buffer = bytes.fromhex(utils.remove_0x_prefix(message))
        elif is_typed_data_message(message):
            buffer = _hash_typed_data_message(message)
        else:
            buffer = _hash_personal_message(message)

        require(len(buffer) == 32, f"Size of message hash buffer should be 32, but now is {len(buffer)}")
        return buffer
    except Exception as e:
        raise ValueError(f"Invalid message. caused by: {repr(e)}, message: {message}") from e

"""Lightweight DBC parser and CAN payload decoder."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict

from utils.config import DEFAULT_DBC_PATH


MESSAGE_PATTERN = re.compile(r"^BO_\s+(?P<msg_id>\d+)\s+(?P<name>\w+):\s+(?P<dlc>\d+)\s+\w+")
SIGNAL_PATTERN = re.compile(
    r"^SG_\s+(?P<name>\w+)\s*:\s*"
    r"(?P<start_bit>\d+)\|(?P<length>\d+)@(?P<byte_order>[01])(?P<signed>[+-])\s*"
    r"\((?P<factor>-?\d+(?:\.\d+)?),(?P<offset>-?\d+(?:\.\d+)?)\)\s*"
    r"\[(?P<minimum>-?\d+(?:\.\d+)?)\|(?P<maximum>-?\d+(?:\.\d+)?)\]\s*"
    r"\"(?P<unit>[^\"]*)\""
)


@dataclass(frozen=True)
class DBCSignal:
    """Decoded representation of a single DBC signal definition."""

    name: str
    start_bit: int
    length: int
    byte_order: int
    is_signed: bool
    factor: float
    offset: float
    minimum: float
    maximum: float
    unit: str


@dataclass
class DBCMessage:
    """Container for a CAN frame definition and its signals."""

    message_id: str
    name: str
    dlc: int
    signals: Dict[str, DBCSignal] = field(default_factory=dict)


class CANDBCDecoder:
    """Parse a subset of DBC and decode byte-aligned payloads."""

    def __init__(self, dbc_path: Path | str = DEFAULT_DBC_PATH) -> None:
        self.dbc_path = Path(dbc_path)
        self.messages = self._parse_dbc(self.dbc_path)

    @staticmethod
    def _normalize_message_id(raw_message_id: int | str) -> str:
        return f"0x{int(str(raw_message_id), 0):X}" if str(raw_message_id).startswith("0x") else f"0x{int(raw_message_id):X}"

    @classmethod
    def _parse_dbc(cls, dbc_path: Path) -> Dict[str, DBCMessage]:
        if not dbc_path.exists():
            return {}

        parsed_messages: Dict[str, DBCMessage] = {}
        current_message: DBCMessage | None = None

        for raw_line in dbc_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line:
                continue

            message_match = MESSAGE_PATTERN.match(line)
            if message_match:
                normalized_id = cls._normalize_message_id(message_match.group("msg_id"))
                current_message = DBCMessage(
                    message_id=normalized_id,
                    name=message_match.group("name"),
                    dlc=int(message_match.group("dlc")),
                )
                parsed_messages[normalized_id] = current_message
                continue

            signal_match = SIGNAL_PATTERN.match(line)
            if signal_match and current_message is not None:
                signal = DBCSignal(
                    name=signal_match.group("name"),
                    start_bit=int(signal_match.group("start_bit")),
                    length=int(signal_match.group("length")),
                    byte_order=int(signal_match.group("byte_order")),
                    is_signed=signal_match.group("signed") == "-",
                    factor=float(signal_match.group("factor")),
                    offset=float(signal_match.group("offset")),
                    minimum=float(signal_match.group("minimum")),
                    maximum=float(signal_match.group("maximum")),
                    unit=signal_match.group("unit"),
                )
                current_message.signals[signal.name] = signal

        return parsed_messages

    @staticmethod
    def _extract_signal_value(payload: bytes, signal: DBCSignal) -> float:
        if signal.start_bit % 8 != 0 or signal.length % 8 != 0:
            raise ValueError(
                f"Only byte-aligned signals are supported: {signal.name}"
            )

        start_byte = signal.start_bit // 8
        width = signal.length // 8
        end_byte = start_byte + width

        if end_byte > len(payload):
            raise ValueError(
                f"Payload too short for signal {signal.name}: expected byte {end_byte}"
            )

        byteorder = "little" if signal.byte_order == 1 else "big"
        raw_value = int.from_bytes(
            payload[start_byte:end_byte],
            byteorder=byteorder,
            signed=signal.is_signed,
        )
        decoded = raw_value * signal.factor + signal.offset
        return round(decoded, 4)

    def decode_payload(self, message_id: str, data_bytes: str) -> Dict[str, float]:
        message = self.messages.get(message_id)
        if message is None:
            return {}

        payload_text = (data_bytes or "").strip().replace(" ", "")
        if payload_text.lower().startswith("0x"):
            payload_text = payload_text[2:]

        try:
            payload = bytes.fromhex(payload_text[: message.dlc * 2].ljust(message.dlc * 2, "0"))
        except ValueError:
            return {}

        decoded_signals: Dict[str, float] = {}
        for signal_name, signal in message.signals.items():
            try:
                decoded_signals[signal_name] = self._extract_signal_value(payload, signal)
            except ValueError:
                continue

        return decoded_signals

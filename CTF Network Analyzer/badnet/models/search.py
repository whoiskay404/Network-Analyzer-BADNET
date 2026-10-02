"""Search-hit model for ``badnet search``.

A hit is a match inside *reassembled* stream payload, so offsets line up with a
hexdump of the stream rather than with any individual packet.  A reassembled
stream can contain holes where packets were never captured, which shifts every
offset after the hole; that limitation is documented on the command, not hidden
here.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class SearchHit:
    """One regex or literal match in a reassembled direction of a stream."""

    stream_id: int
    direction: str
    """``client_to_server`` or ``server_to_client``."""
    offset: int
    """Byte offset of the match within the reassembled direction."""
    length: int
    """Length of the matched text in bytes."""
    match: str
    """The matched text, decoded with ``errors="replace"``."""
    context: str = ""
    """Surrounding bytes, decoded the same way, for orientation."""
    context_offset: int = 0
    """Byte offset of ``context`` within the reassembled direction."""
    source: str = ""
    """Where the searched bytes came from, e.g. ``tcp-stream-3``."""
    truncated: bool = False
    """True when the match was cut short by the preview limit."""

    def to_dict(self) -> dict[str, object]:
        """Serialise for NDJSON/JSON."""
        return {
            "stream_id": self.stream_id,
            "direction": self.direction,
            "offset": self.offset,
            "length": self.length,
            "match": self.match,
            "context": self.context,
            "context_offset": self.context_offset,
            "source": self.source,
            "truncated": self.truncated,
        }

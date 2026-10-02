"""Parsing layer: capture readers.

A reader turns bytes into :class:`~badnet.models.packet.NormalizedPacket` rows
(or protocol-specific rows).  Readers never interpret or judge anything - all
analysis happens in :mod:`badnet.analyzers`.
"""

from __future__ import annotations

"""Typed data model shared by every layer.

These dataclasses are the contract between ``parsing`` -> ``analysis`` ->
``detection`` -> ``reporting``.  Each one knows how to serialise itself to plain
JSON-compatible dicts, which is what the case store and the reports consume.
"""

from __future__ import annotations

from badnet.models.artifact import Artifact, ExtractionMethod
from badnet.models.case import CaseInfo, CaseMetadata
from badnet.models.connection import Connection
from badnet.models.dns import DnsRecord, DnsStats, DnsTunnelCandidate
from badnet.models.finding import Confidence, Finding, Severity
from badnet.models.http import HttpExchange, HttpRequest, HttpResponse
from badnet.models.packet import NormalizedPacket
from badnet.models.pcapinfo import PcapInfo, ProtocolCount
from badnet.models.stream import StreamDirection, StreamInfo
from badnet.models.tls import CertificateInfo, TlsHandshake, TlsSession

__all__ = [
    "Artifact",
    "CaseInfo",
    "CaseMetadata",
    "CertificateInfo",
    "Confidence",
    "Connection",
    "DnsRecord",
    "DnsStats",
    "DnsTunnelCandidate",
    "ExtractionMethod",
    "Finding",
    "HttpExchange",
    "HttpRequest",
    "HttpResponse",
    "NormalizedPacket",
    "PcapInfo",
    "ProtocolCount",
    "Severity",
    "StreamDirection",
    "StreamInfo",
    "TlsHandshake",
    "TlsSession",
]

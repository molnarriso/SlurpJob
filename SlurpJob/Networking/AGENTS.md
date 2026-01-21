c:\Development\SlurpJob\SlurpJob\Networking\AGENTS.md

This folder contains low-level networking components for the "Sponge".

## TcpSponge.cs
Handles incoming TCP connections, payload ingestion, and timeout management.

## UdpSponge.cs
Handles UDP datagram ingestion.

## LinuxInterop.cs
Provides P/Invoke wrappers or logic for resolving original destination ports on Linux (Netfilter/IPTables interaction).

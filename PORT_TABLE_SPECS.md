# Port Table Specification

This document describes the structure and logic of `port_table.csv`, generated for use in the SlurpJob dashboard and ingestion pipeline.

## File Information
- **Path**: `./port_table.csv`
- **Rows**: 65,537 (Header + 65,536 ports)
- **Indexing**: 1-to-1 Mapping. Line `N` corresponds to Port `N-1`.
  - Header: Line 1
  - Port 0: Line 2
  - Port 80: Line 82
  - Port 65535: Line 65537

## Columns
| Column | Type | Description |
| :--- | :--- | :--- |
| **Port** | Int | Port number (0-65535). Guaranteed contiguous. |
| **TCP** | String | `Yes`, `No`, or `[empty]`. Indicates service availability. |
| **UDP** | String | `Yes`, `No`, or `[empty]`. Indicates service availability. |
| **SCTP** | String | `Yes`, or `[empty]`. (Very rare, only 12 entries). |
| **DCCP** | String | `Yes`, or `[empty]`. (Extremely rare, only 3 entries). |
| **Description** | String | Full original description from Wikipedia (merged if multiple services on same port). |
| **ShortDescription** | String | UI-optimized description, shortened to < 64 characters (mostly). |

## Data Processing History
1. **Flattening**: Ranges from the wiki (e.g., `100-200`) were expanded into individual lines.
2. **Merging**: If a port had multiple entries (e.g., one for TCP and one for UDP), the `Description` fields were concatenated with `; ` and the protocol flags were unified.
3. **Normalization**:
   - `Assigned` and `Unofficial` values were converted to `Yes`.
   - `Reserved` was converted to `No`.
   - Citation markers (e.g., `[10]`, `[citation needed]`) and Unicode characters were removed/normalized to ASCII.
4. **Shortening**:
   - Technical descriptions were condensed for dashboard display using manual and pattern-based shortening.
   - Example: `League of Legends [...]` -> `LoL`

## Usage for C# Integration
The file is designed for direct array indexing. A C# agent can load this into a `Port[65536]` array where `array[portNumber]` maps directly to the data.

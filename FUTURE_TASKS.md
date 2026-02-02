## UI/UX Improvements

### Attack Wiki
When an attack is detected, user should be able to click on it and view the attack details, what it does, how it works, etc. Maybe somehow the attack details should be accessible from timeline tags list, but dunno how, since there is not enough space. Or is there? Anyway, in both cases, modal should be used. Where should the attack details be stored?

### Mobile Ready View
Where the three panels are stacked vertically. Distinguish between modes by available screen space.

### Better 2D Map
Antarctica is too large, Europe too small.

### Handle testing against data
How should the tests proceed when no local db ? Should we ship example testing db in repo ? Some better solution ? Goal is to have tests run fast and not depend on external resources.

### Containerization

make this deployable as container

### Manual Filter Addition (Coming Soon)

This feature allows users to manually add filters (e.g., specific country or port) via a dropdown menu in the FilterBar, instead of relying on clicks.

#### Steps to Implement

1.  **Update FilterBar.razor**:
    - Build out the `add-menu` with sub-menus.
    - **Country**: Simple text input (ISO code) + "Add" button.
    - **Port**: Number input + "Add" button.
    - **Protocol**: Radio buttons (TCP/UDP) or select.

2.  **Filter Logic**:
    - Use `FilterService.AddFilter(new CountryFilter(code))` etc.
    - Ensure validation (valid standard ISO codes, port range 1-65535).

3.  **UI Example (Razor)**:
    ```razor
    <div class="menu-section">
        <label>Country</label>
        <div class="input-group">
            <input @bind="_newCountryCode" placeholder="US, CN..." />
            <button @onclick="AddCountryFilter">Add</button>
        </div>
    </div>
    ```

4.  **Backend Support**:
    - `FilterService` is already ready. No backend changes needed.

## Classifier Improvements

> **Analysis Date:** 2026-02-01 | **DB Size:** 150,962 incidents | **Unclassified:** 86,129 (57%)

### Priority 1: TLS ClientHello (~15,579 hits)
- **Signature:** `0x1603` prefix (TLS record layer)
- **Detection:** First 2 bytes = `16 03` (Content Type: Handshake, Version: TLS)
- **Variants:** `0x160301` (TLS 1.0), `0x160303` (TLS 1.2)
- **Intent:** Recon (service probing for HTTPS/encrypted services)
- **Protocol:** TLS

### Priority 2: RDP/X.224 (~13,268 hits)
- **Signature:** `0x0300` prefix (X.224 Connection Request)
- **Detection:** First 2 bytes = `03 00` (TPKT version 3)
- **Intent:** Exploit (BlueKeep CVE-2019-0708, RDP brute-force)
- **Protocol:** RDP
- **Common ports:** 3389, but seen on many ports

### Priority 3: JSON-RPC/Ethereum (~1,482 hits)
- **Signature:** `{"id":` (ASCII: `7B226964223A`)
- **Detection:** Starts with `{"id":1,` or similar JSON-RPC structure
- **Intent:** Recon (Ethereum node discovery, API scanning)
- **Protocol:** JSONRPC
- **Sub-patterns:** eth_blockNumber, eth_getBalance, web3_clientVersion

### Priority 4: Redis RESP (~904 hits)
- **Signature:** `*1\r\n$4\r\n` (RESP array)
- **Detection:** Starts with `*` followed by RESP protocol commands
- **Common commands:** `INFO`, `PING`, `CONFIG GET`
- **Intent:** Exploit (unauthenticated Redis access)
- **Protocol:** Redis

### Priority 5: Java RMI (~866 hits)
- **Signature:** `JRMI` (ASCII: `4A524D49`)
- **Detection:** First 4 bytes = `JRMI`
- **Intent:** Exploit (Java deserialization, CVE-2017-3241)
- **Protocol:** RMI

### Priority 6: WebLogic T3 (~752 hits)
- **Signature:** `t3 12.` (ASCII text handshake)
- **Detection:** Starts with `t3 ` followed by version
- **Intent:** Exploit (CVE-2020-14882, CVE-2019-2725, CVE-2017-10271)
- **Protocol:** T3
- **High severity:** Known RCE vectors

### Priority 7: SMB (~880 hits)
- **Signature:** `0x000000..FF534D42` (SMB header with null bytes)
- **Detection:** Contains `\xFF SMB` magic
- **Intent:** Exploit (EternalBlue MS17-010, SMB enumeration)
- **Protocol:** SMB

### Priority 8: AMQP (~749 hits)
- **Signature:** `AMQP` (ASCII: `414D5150`)
- **Detection:** First 4 bytes = `AMQP`
- **Intent:** Recon (RabbitMQ/message queue discovery)
- **Protocol:** AMQP

### Priority 9: CORBA/IIOP (~858 hits)
- **Signature:** `GIOP` (ASCII: `47494F50`)
- **Detection:** First 4 bytes = `GIOP`
- **Intent:** Recon (CORBA service discovery)
- **Protocol:** GIOP

### Priority 10: Bitcoin P2P (~753 hits)
- **Signature:** `0xF9BEB4D9` (mainnet magic)
- **Detection:** First 4 bytes = Bitcoin magic bytes
- **Intent:** Recon (cryptocurrency node discovery)
- **Protocol:** Bitcoin

### Lower Priority

| Protocol | Hits | Signature | Notes |
|----------|------|-----------|-------|
| HTTP/2 | ~747 | `PRI * HTTP/2.0` | HTTP/2 connection preface |
| Telnet HELP | ~895 | `HELP\r\n` | Generic banner grab |
| MGLNDD Scanner | ~1,329 | `MGLNDD_` | Scanning tool fingerprint |
| TNMP | ~871 | `TNMP` | Unknown protocol |
| DmdT | ~863 | `DmdT` | Unknown scanner |
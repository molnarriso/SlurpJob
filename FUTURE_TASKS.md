## UI/UX Improvements

### Attack Wiki
When an attack is detected, user should be able to click on it and view the attack details, what it does, how it works, etc. Maybe somehow the attack details should be accessible from timeline tags list, but dunno how, since there is not enough space. Or is there? Anyway, in both cases, modal should be used. Where should the attack details be stored?

### Mobile Ready View
Where the three panels are stacked vertically. Distinguish between modes by available screen space.

### Better 2D Map
Antarctica is too large, Europe too small.

## Classifier Improvements

### VNC Classifier
- Detect RFB protocol handshake (`RFB 003.008`, `RFB 003.003`, `RFB 003.007`)
- Set `PayloadProtocol = VNC`
- Set `Intent = Exploit` (vulnerable remote desktop targeting)
- Create `VNCClassifier.cs` implementing `IInboundClassifier`
- Add unit tests with real VNC handshake payloads

### HTTP Path Classifiers
Expand existing `HTTPClassifier` or create specialized classifiers:
- **Admin Panel Probe:** `/admin`, `/wp-admin`, `/phpmyadmin`, `/cpanel`
- **Path Traversal:** `/../`, `..\\`, `%2e%2e`, URL-encoded variants
- **Web Shell Upload:** `/shell.php`, `/c99.php`, `/r57.php`, `/cmd.asp`
- **Config File Probe:** Expand `EnvFileProbe` to include `/.git/config`, `/web.config`, `/config.php`
- Set appropriate `Intent` values (Exploit vs Recon)
- Use local `slurp.db` to validate against real HTTP attack data

### SIP Sub-Classification
Enhance existing `SIPClassifier` to distinguish SIP methods:
- `INVITE` → "SIP Hijacking Attempt" (Intent: Exploit)
- `REGISTER` → "SIP Account Enumeration" (Intent: Recon)
- `OPTIONS` → "SIP Service Discovery" (Intent: Recon)
- `ACK`, `BYE`, `CANCEL` → Additional method tracking
- Return more specific `ClassifierName` based on SIP method
- Add unit tests for each SIP method variant
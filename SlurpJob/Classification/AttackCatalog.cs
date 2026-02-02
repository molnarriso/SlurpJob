using System.Text.Json;
using System.Reflection;

namespace SlurpJob.Classification;

/// <summary>
/// Static catalog of attack information for educational display.
/// Maps classifier IDs to human-readable explanations.
/// Loaded from attack_catalog.json
/// </summary>
public static class AttackCatalog
{
    private static readonly Dictionary<string, AttackInfo> _catalog = new(StringComparer.OrdinalIgnoreCase);
    private static readonly Dictionary<string, AttackInfo> _protocolFallbacks = new(StringComparer.OrdinalIgnoreCase);

    static AttackCatalog()
    {
        try
        {
            var jsonPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Classification", "attack_catalog.json");
            
            // Fallback to project structure if running in dev without copy (optional safety)
            if (!File.Exists(jsonPath))
            {
                jsonPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "attack_catalog.json");
            }

            if (File.Exists(jsonPath))
            {
                var json = File.ReadAllText(jsonPath);
                var items = JsonSerializer.Deserialize<List<AttackInfo>>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                
                if (items != null)
                {
                    foreach (var item in items)
                    {
                        Register(item);
                        
                        // Register protocol fallback if specified
                        if (!string.IsNullOrEmpty(item.Protocol))
                        {
                            _protocolFallbacks[item.Protocol] = item;
                        }
                    }
                }
            }
            else
            {
                // Fallback or empty if file not found (logging would be good here but it's static)
                Console.WriteLine($"[Error] AttackCatalog: Could not find attack_catalog.json at {jsonPath}");
                Register(new AttackInfo
                {
                    Id = "unknown",
                    Title = "Unclassified Traffic (Catalog Missing)",
                    WhatIsIt = "The attack catalog file could not be loaded.",
                    Impact = "Unknown.",
                    TechnicalNote = "Check server logs for missing attack_catalog.json."
                });
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Error] AttackCatalog: Failed to load catalog. {ex.Message}");
        }

        // Ensure unknown exists
        if (!_catalog.ContainsKey("unknown"))
        {
            Register(new AttackInfo
            {
                Id = "unknown",
                Title = "Unclassified Traffic",
                WhatIsIt = "This traffic doesn't match any known attack pattern yet.",
                Impact = "Unknown.",
                TechnicalNote = "Manual analysis required."
            });
        }
    }

    private static void Register(AttackInfo info)
    {
        if (!string.IsNullOrEmpty(info.Id))
        {
            _catalog[info.Id] = info;
        }
    }

    /// <summary>
    /// Get attack info by attack ID, with fallback to protocol-level or unknown.
    /// </summary>
    /// <param name="classifierId">Attack ID (e.g., "rdp-bluekeep", "tls-scanning") from IncidentLog.AttackId</param>
    /// <param name="protocol">Optional protocol fallback (e.g., "TLS", "RDP")</param>
    public static AttackInfo Get(string? classifierId, string? protocol = null)
    {
        // Try exact ID match (but not "unknown" - that's the fallback)
        if (!string.IsNullOrEmpty(classifierId) && classifierId != "unknown" && _catalog.TryGetValue(classifierId, out var info))
            return info;
        
        // Try protocol fallback
        if (!string.IsNullOrEmpty(protocol) && _protocolFallbacks.TryGetValue(protocol, out var protoInfo))
            return protoInfo;
        
        // Return unknown
        if (_catalog.TryGetValue("unknown", out var unknownInfo))
            return unknownInfo;

        return new AttackInfo 
        { 
            Title = "Unknown", 
            Id = "unknown",
            WhatIsIt = "Unclassified traffic.",
            Impact = "Unknown."
        };
    }

    /// <summary>
    /// Check if a specific attack ID has catalog entry.
    /// </summary>
    /// <param name="classifierId">Attack ID to check</param>
    public static bool HasEntry(string classifierId) => _catalog.ContainsKey(classifierId);
}

namespace SlurpJob.Classification;

/// <summary>
/// Information about an attack type for educational display.
/// </summary>
public class AttackInfo
{
    /// <summary>
    /// Stable identifier matching ClassificationResult.Id
    /// </summary>
    public required string Id { get; init; }
    
    /// <summary>
    /// Short title for the attack type
    /// </summary>
    public required string Title { get; init; }
    
    /// <summary>
    /// One sentence explaining what the bot is trying to do
    /// </summary>
    public required string WhatIsIt { get; init; }
    
    /// <summary>
    /// What would happen if the attack succeeded
    /// </summary>
    public required string Impact { get; init; }
    
    /// <summary>
    /// Technical details or interesting facts
    /// </summary>
    public string? TechnicalNote { get; init; }
    
    /// <summary>
    /// External reference links (CVE database, MITRE ATT&CK, etc.)
    /// </summary>
    public string[] References { get; init; } = [];
}

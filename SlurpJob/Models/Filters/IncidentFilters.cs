using SlurpJob.Data;

namespace SlurpJob.Models.Filters;

// --- Core Definitions ---

public enum FilterVerb 
{ 
    Is,        // Equals
    IsNot,     // Not equals
    InRange,   // For numeric fields (Port)
    NotInRange // For numeric fields (Port)
}

public interface IIncidentFilter
{
    string FilterType { get; }           // "country", "classifier", "port", etc.
    string DisplayLabel { get; }         // Human-readable label for UI
    FilterVerb Verb { get; set; }
    FilterVerb[] SupportedVerbs { get; } // What verbs this filter type supports
    
    bool Matches(IncidentLog incident);  // In-memory predicate for live filtering
    IQueryable<IncidentLog> ApplyToQuery(IQueryable<IncidentLog> query);
}

// --- Implementations ---

public class CountryFilter : IIncidentFilter
{
    public string FilterType => "country";
    public string CountryCode { get; }
    public string CountryName { get; }
    public FilterVerb Verb { get; set; } = FilterVerb.Is;
    public FilterVerb[] SupportedVerbs => [FilterVerb.Is, FilterVerb.IsNot];
    
    public string DisplayLabel => $"{CountryCode}";
    
    public CountryFilter(string countryCode, string countryName = "")
    {
        CountryCode = countryCode;
        CountryName = countryName;
    }
    
    public bool Matches(IncidentLog incident) => Verb switch
    {
        FilterVerb.Is => incident.CountryCode == CountryCode,
        FilterVerb.IsNot => incident.CountryCode != CountryCode,
        _ => true
    };
    
    public IQueryable<IncidentLog> ApplyToQuery(IQueryable<IncidentLog> query) => Verb switch
    {
        FilterVerb.Is => query.Where(i => i.CountryCode == CountryCode),
        FilterVerb.IsNot => query.Where(i => i.CountryCode != CountryCode),
        _ => query
    };
}

public class ClassifierFilter : IIncidentFilter
{
    public string FilterType => "classifier";
    public string ClassifierName { get; }
    public FilterVerb Verb { get; set; } = FilterVerb.Is;
    public FilterVerb[] SupportedVerbs => [FilterVerb.Is, FilterVerb.IsNot];
    
    public string DisplayLabel => $"{ClassifierName}";
    
    public ClassifierFilter(string classifierName)
    {
        ClassifierName = classifierName;
    }
    
    public bool Matches(IncidentLog incident) => Verb switch
    {
        FilterVerb.Is => incident.ClassifierName == ClassifierName,
        FilterVerb.IsNot => incident.ClassifierName != ClassifierName,
        _ => true
    };
    
    public IQueryable<IncidentLog> ApplyToQuery(IQueryable<IncidentLog> query) => Verb switch
    {
        FilterVerb.Is => query.Where(i => i.ClassifierName == ClassifierName),
        FilterVerb.IsNot => query.Where(i => i.ClassifierName != ClassifierName),
        _ => query
    };
}

public class AttackIdFilter : IIncidentFilter
{
    public string FilterType => "attackId";
    public string AttackId { get; }
    public FilterVerb Verb { get; set; } = FilterVerb.Is;
    public FilterVerb[] SupportedVerbs => [FilterVerb.Is, FilterVerb.IsNot];
    
    public string DisplayLabel => $"Attack: {AttackId}";
    
    public AttackIdFilter(string attackId)
    {
        AttackId = attackId;
    }
    
    public bool Matches(IncidentLog incident) => Verb switch
    {
        FilterVerb.Is => incident.AttackId == AttackId,
        FilterVerb.IsNot => incident.AttackId != AttackId,
        _ => true
    };
    
    public IQueryable<IncidentLog> ApplyToQuery(IQueryable<IncidentLog> query) => Verb switch
    {
        FilterVerb.Is => query.Where(i => i.AttackId == AttackId),
        FilterVerb.IsNot => query.Where(i => i.AttackId != AttackId),
        _ => query
    };
}

public class PortFilter : IIncidentFilter
{
    public string FilterType => "port";
    public int Port { get; }
    public int? PortEnd { get; }  // For range mode
    public FilterVerb Verb { get; set; } = FilterVerb.Is;
    public FilterVerb[] SupportedVerbs => [FilterVerb.Is, FilterVerb.IsNot, FilterVerb.InRange, FilterVerb.NotInRange];
    
    public string DisplayLabel => PortEnd.HasValue 
        ? $"Port {Port}-{PortEnd}" 
        : $"Port {Port}";
    
    public PortFilter(int port, int? portEnd = null)
    {
        Port = port;
        PortEnd = portEnd;
    }
    
    public bool Matches(IncidentLog incident) => Verb switch
    {
        FilterVerb.Is => incident.TargetPort == Port,
        FilterVerb.IsNot => incident.TargetPort != Port,
        FilterVerb.InRange => incident.TargetPort >= Port && incident.TargetPort <= (PortEnd ?? Port),
        FilterVerb.NotInRange => incident.TargetPort < Port || incident.TargetPort > (PortEnd ?? Port),
        _ => true
    };
    
    public IQueryable<IncidentLog> ApplyToQuery(IQueryable<IncidentLog> query) => Verb switch
    {
        FilterVerb.Is => query.Where(i => i.TargetPort == Port),
        FilterVerb.IsNot => query.Where(i => i.TargetPort != Port),
        FilterVerb.InRange => query.Where(i => i.TargetPort >= Port && i.TargetPort <= (PortEnd ?? Port)),
        FilterVerb.NotInRange => query.Where(i => i.TargetPort < Port || i.TargetPort > (PortEnd ?? Port)),
        _ => query
    };
}

public class IntentFilter : IIncidentFilter
{
    public string FilterType => "intent";
    public string Intent { get; }
    public FilterVerb Verb { get; set; } = FilterVerb.Is;
    public FilterVerb[] SupportedVerbs => [FilterVerb.Is, FilterVerb.IsNot];
    
    public string DisplayLabel => $"Intent: {Intent}";
    
    public IntentFilter(string intent)
    {
        Intent = intent;
    }
    
    public bool Matches(IncidentLog incident) => Verb switch
    {
        FilterVerb.Is => incident.Intent == Intent,
        FilterVerb.IsNot => incident.Intent != Intent,
        _ => true
    };
    
    public IQueryable<IncidentLog> ApplyToQuery(IQueryable<IncidentLog> query) => Verb switch
    {
        FilterVerb.Is => query.Where(i => i.Intent == Intent),
        FilterVerb.IsNot => query.Where(i => i.Intent != Intent),
        _ => query
    };
}

public class ProtocolFilter : IIncidentFilter
{
    public string FilterType => "protocol";
    public string Protocol { get; }
    public FilterVerb Verb { get; set; } = FilterVerb.Is;
    public FilterVerb[] SupportedVerbs => [FilterVerb.Is, FilterVerb.IsNot];
    
    public string DisplayLabel => $"{Protocol}";
    
    public ProtocolFilter(string protocol)
    {
        Protocol = protocol;
    }
    
    public bool Matches(IncidentLog incident) => Verb switch
    {
        FilterVerb.Is => incident.Protocol == Protocol,
        FilterVerb.IsNot => incident.Protocol != Protocol,
        _ => true
    };
    
    public IQueryable<IncidentLog> ApplyToQuery(IQueryable<IncidentLog> query) => Verb switch
    {
        FilterVerb.Is => query.Where(i => i.Protocol == Protocol),
        FilterVerb.IsNot => query.Where(i => i.Protocol != Protocol),
        _ => query
    };
}

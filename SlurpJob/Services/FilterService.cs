using SlurpJob.Models;
using SlurpJob.Models.Filters;

namespace SlurpJob.Services;

public class FilterService
{
    public List<IIncidentFilter> ActiveFilters { get; } = new();
    public event Action? OnFiltersChanged;
    
    // Time range kept separate for UI convenience, but could be refactored here if needed
    // Currently Dashboard.razor manages time range.
    
    public void AddFilter(IIncidentFilter filter)
    {
        // Optional: Check for duplicates or merge logic here if needed
        ActiveFilters.Add(filter);
        OnFiltersChanged?.Invoke();
    }
    
    public void RemoveFilter(IIncidentFilter filter)
    {
        ActiveFilters.Remove(filter);
        OnFiltersChanged?.Invoke();
    }
    
    public void SetVerb(IIncidentFilter filter, FilterVerb verb)
    {
        filter.Verb = verb;
        OnFiltersChanged?.Invoke();
    }
    
    public void ClearAll()
    {
        ActiveFilters.Clear();
        OnFiltersChanged?.Invoke();
    }
    
    // For LiveFeed (in-memory) - AND logic
    public bool MatchesAll(IncidentLog incident)
    {
        if (ActiveFilters.Count == 0) return true;
        return ActiveFilters.All(f => f.Matches(incident));
    }
    
    // For DB queries - AND logic
    public IQueryable<IncidentLog> ApplyAll(IQueryable<IncidentLog> query)
    {
        foreach (var filter in ActiveFilters)
        {
            query = filter.ApplyToQuery(query);
        }
        return query;
    }
}

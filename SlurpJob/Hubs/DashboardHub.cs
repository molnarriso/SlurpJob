using Microsoft.AspNetCore.SignalR;
using SlurpJob.Models;

namespace SlurpJob.Hubs;

public class DashboardHub : Hub
{
    // Simple hub to push updates to clients
    public async Task SendUpdate(IncidentLog log)
    {
        await Clients.All.SendAsync("ReceiveIncident", log);
    }
}

using SlurpJob.Components;
using SlurpJob.Services;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();
    
builder.Services.AddServerSideBlazor()
    .AddCircuitOptions(options => { options.DetailedErrors = true; })
    .AddHubOptions(options => {
        options.EnableDetailedErrors = true;
        // Disable compression to avoid proxy issues
        // options.HandshakeTimeout = TimeSpan.FromSeconds(30); 
    });

builder.Services.AddSignalR(); // NEW: SignalR

// Proxy Support
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor | 
                               Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedProto;
});

// SlurpJob Services
builder.Services.AddSingleton<SlurpJob.Services.PortTableService>();
builder.Services.AddSingleton<SlurpJob.Services.IngestionService>();
builder.Services.AddHostedService(p => p.GetRequiredService<SlurpJob.Services.IngestionService>());

// Classifiers (one per pattern, all run and results merged)
builder.Services.AddSingleton<SlurpJob.Classification.IInboundClassifier, SlurpJob.Classification.HTTPClassifier>();
builder.Services.AddSingleton<SlurpJob.Classification.IInboundClassifier, SlurpJob.Classification.SSHClassifier>();
builder.Services.AddSingleton<SlurpJob.Classification.IInboundClassifier, SlurpJob.Classification.Log4JClassifier>();
builder.Services.AddSingleton<SlurpJob.Classification.IInboundClassifier, SlurpJob.Classification.EnvProbeClassifier>();
builder.Services.AddSingleton<SlurpJob.Classification.IInboundClassifier, SlurpJob.Classification.EmptyScanClassifier>();
builder.Services.AddSingleton<SlurpJob.Classification.IInboundClassifier, SlurpJob.Classification.SIPClassifier>();
builder.Services.AddSingleton<SlurpJob.Classification.IInboundClassifier, SlurpJob.Classification.SSDPClassifier>();

builder.Services.AddDbContextFactory<SlurpJob.Data.SlurpContext>(options =>
    options.UseSqlite("Data Source=slurp.db"));

var app = builder.Build();

// Ensure DB Created
using (var scope = app.Services.CreateScope())
{
    var factory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<SlurpJob.Data.SlurpContext>>();
    using var db = factory.CreateDbContext();
    db.Database.Migrate();
}



// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseForwardedHeaders(); // PROXY SUPPORT
    app.UseHsts();
}

app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();
    
app.MapHub<SlurpJob.Hubs.DashboardHub>("/dashboardHub"); // NEW: Map Hub

app.Run("http://localhost:5000");
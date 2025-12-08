using SlurpJob.Components;
using SlurpJob.Services;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// SlurpJob Services
builder.Services.AddSingleton<SlurpJob.Services.MemoryStore>();
builder.Services.AddSingleton<SlurpJob.Services.IngestionService>();
builder.Services.AddHostedService(p => p.GetRequiredService<SlurpJob.Services.IngestionService>());
builder.Services.AddHostedService<SlurpJob.Services.PersistenceWorker>();
builder.Services.AddHostedService<SlurpJob.Services.PanicService>();

builder.Services.AddDbContext<SlurpJob.Data.SlurpContext>(options =>
    options.UseSqlite("Data Source=slurp.db"));

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}


// app.UseHttpsRedirection();


app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();

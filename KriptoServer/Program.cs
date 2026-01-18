using KriptoServer.Hubs;
using Microsoft.AspNetCore.ResponseCompression;

var builder = WebApplication.CreateBuilder(args);

// 1. SignalR Servisini Ekle
builder.Services.AddSignalR();

// 2. CORS Politikasý (Blazor'ýn baðlanabilmesi için þart)
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll",
        builder =>
        {
            builder
                .AllowAnyMethod()
                .AllowAnyHeader()
                .SetIsOriginAllowed((host) => true) // Localhost için izin ver
                .AllowCredentials();
        });
});

var app = builder.Build();

// 3. CORS'u Aktif Et
app.UseCors("AllowAll");

// 4. Hub Rotasýný Tanýmla
// Blazor tarafýnda .WithUrl("/cryptohub") demiþtik, iþte o burasý.
app.MapHub<CryptoHub>("/cryptohub");

// Test için basit bir endpoint (Opsiyonel)
app.MapGet("/", () => "CryptoServer Calisiyor! SignalR Hub: /cryptohub");

app.Run();
using CryptoLibrary;
using KriptoServer.Hubs;
using Microsoft.AspNetCore.ResponseCompression;

var builder = WebApplication.CreateBuilder(args);

// The server identity key comes from configuration.
var seedHex = builder.Configuration["ServerIdentity:PrivateKeySeed"]
    ?? throw new InvalidOperationException(
        "ServerIdentity:PrivateKeySeed yapılandırılmamış. appsettings.json veya ortam değişkenini kontrol edin.");

var serverIdentity = IdentityService.CreateFromPrivateSeed(Convert.FromHexString(seedHex));

// The configured seed must match the public key pinned in the client.
if (!serverIdentity.GetPublicKey().SequenceEqual(ProtocolIdentity.GetPinnedServerPublicKey()))
    throw new InvalidOperationException(
        "ServerIdentity:PrivateKeySeed, istemcide pin edilmiş public key ile eşleşmiyor.");

builder.Services.AddSingleton(serverIdentity);

builder.Services.AddSignalR();

// The Blazor client is served from another port, so CORS is needed.
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll",
        corsBuilder =>
        {
            corsBuilder
                .AllowAnyMethod()
                .AllowAnyHeader()
                .SetIsOriginAllowed((_) => true)
                .AllowCredentials();
        });
});

var app = builder.Build();

app.UseCors("AllowAll");

app.MapHub<CryptoHub>("/cryptohub");

app.MapGet("/", () => "CryptoServer Calisiyor! SignalR Hub: /cryptohub");

app.Run();

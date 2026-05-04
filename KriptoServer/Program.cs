using CryptoLibrary;
using KriptoServer.Hubs;
using Microsoft.AspNetCore.ResponseCompression;

var builder = WebApplication.CreateBuilder(args);

// 1. Sunucu kimlik anahtarını yapılandırmadan yükle
var seedHex = builder.Configuration["ServerIdentity:PrivateKeySeed"]
    ?? throw new InvalidOperationException(
        "ServerIdentity:PrivateKeySeed yapılandırılmamış. appsettings.json veya ortam değişkenini kontrol edin.");

var serverIdentity = IdentityService.CreateFromPrivateSeed(Convert.FromHexString(seedHex));

// Güvenlik: yapılandırılan seed'in pinned public key ile eşleştiğini doğrula
if (!serverIdentity.GetPublicKey().SequenceEqual(ProtocolIdentity.GetPinnedServerPublicKey()))
    throw new InvalidOperationException(
        "ServerIdentity:PrivateKeySeed, istemcide pin edilmiş public key ile eşleşmiyor.");

builder.Services.AddSingleton(serverIdentity);

// 2. SignalR Servisini Ekle
builder.Services.AddSignalR();

// 3. CORS Politikası (Blazor'ın bağlanabilmesi için şart)
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

// 4. CORS'u Aktif Et
app.UseCors("AllowAll");

// 5. Hub Rotasını Tanımla
app.MapHub<CryptoHub>("/cryptohub");

app.MapGet("/", () => "CryptoServer Calisiyor! SignalR Hub: /cryptohub");

app.Run();

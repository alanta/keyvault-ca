using KeyVaultCa.Cli.Handlers;
using Microsoft.Extensions.Hosting;

IHostBuilder builder = Host.CreateDefaultBuilder(args);
builder.UseCommandLineApplication<CliApp>(args, CliApp.Configure);

var host = builder.Build();
CliApp.ServiceProvider = host.Services;

await host.RunCommandLineApplicationAsync();








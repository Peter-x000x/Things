using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Core;
using System;
using System.Security.Principal;
using Things.Services;

namespace Things
{
    internal class ThingsServer
    {
        public static void Main(string[] args)
        {
            AppDomain.CurrentDomain.SetPrincipalPolicy(PrincipalPolicy.WindowsPrincipal);

            WebApplicationBuilder builder = WebApplication.CreateBuilder(new WebApplicationOptions
            {
                Args = args,
                ContentRootPath = WindowsServiceHelpers.IsWindowsService()
                    ? AppContext.BaseDirectory
                    : default
            });

            Log.Logger = new LoggerConfiguration()
                .WriteTo.Console()
                .WriteTo.File("C:\\Projects\\Things\\logs\\log-.txt", rollingInterval: RollingInterval.Day)
                .CreateLogger();

            builder.Logging.AddSerilog();

            builder.Host.UseWindowsService();

            IConfigurationSection config = builder.Configuration.GetSection("WorkerSettings");
            builder.Services.Configure<WorkerSettings>(config);

            builder.Services.AddHostedService<Worker>();
            builder.Services.AddGrpc();
            builder.WebHost.ConfigureKestrel(options =>
            {
                string pipeName = config.GetValue<string>("PipeName");
                options.Listen(new NamedPipeEndPoint(pipeName), listenOptions =>
                {
                    listenOptions.Protocols = HttpProtocols.Http2;
                });
            });

            WebApplication app = builder.Build();

            app.MapGrpcService<GreeterService>();

            app.Run();
        }
    }
}

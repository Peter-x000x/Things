using Grpc.Net.Client;
using System;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Things;

namespace Client
{
    internal class ThingsClient
    {
        private static async Task Main(string[] args)
        {
            AppDomain.CurrentDomain.SetPrincipalPolicy(PrincipalPolicy.WindowsPrincipal);
            Console.WriteLine("Client identity: " + Thread.CurrentPrincipal?.Identity?.Name);
            try
            {
                await MakeGrpcRequest();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString(), e);
            }

            Console.WriteLine("Press any key to exit");
            Console.ReadKey();
        }

        private static async Task MakeGrpcRequest()
        {
            Console.WriteLine("Making gRPC request...");
            using var channel = GrpcChannel.ForAddress("http://localhost:5001", new GrpcChannelOptions
            {
                HttpHandler = CreateHandler("Pipe-1", impersonationLevel: TokenImpersonationLevel.Impersonation)
            });
            var client = new Greeter.GreeterClient(channel);

            var reply = await client.SayHelloAsync(new HelloRequest { Name = "GreeterClient" });
            Console.WriteLine("Greeting: " + reply.Message);
        }

        private static SocketsHttpHandler CreateHandler(string pipeName, TokenImpersonationLevel? impersonationLevel = null)
        {
            var httpHandler = new SocketsHttpHandler();
            httpHandler.SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, _, _, _) => true
            };

            var connectionFactory = new NamedPipesConnectionFactory(pipeName, impersonationLevel);
            httpHandler.ConnectCallback = connectionFactory.ConnectAsync;

            return httpHandler;
        }
    }
}
using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using TitaniumWebProxyWrapper;

namespace WrapperExample
{
    class Program
    {
        static void Main(string[] args)
        {
            PacketSniffer ps = new PacketSniffer(IPAddress.Any);
            ps.SetListeningActions(OnRequest,OnResponse,OnError);

            Console.Read();
            ps.Dispose();
        }


        private static void OnRequest(ref Dictionary<string, string> headers, ref string url, ref string parameters, ref string redirectUrl, ref string cancelRequestHtml)
        {
            Console.WriteLine($"REQUEST -> Url: {url}");
        }

        private static void OnResponse(ref Dictionary<string, string> headers, ref string url, ref string parameters, ref string html)
        {
            Console.WriteLine($"RESPONSE -> Url: {url}");
        }

        private static void OnError(PacketType type, Dictionary<string, string> headers, string url, string errorMessage)
        {
            Console.WriteLine($"ERROR -> Message: {errorMessage}");
        }

    }
}

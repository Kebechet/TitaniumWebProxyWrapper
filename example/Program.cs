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


            Task.Delay(100000).Wait();
            ps.Dispose();
        }


        private static bool OnRequest(ref Dictionary<string, string> headers, ref string url, ref string parameters, out bool abortRequest, ref string redirectUrl, ref string cancelRequestHtml)
        {
            abortRequest = false;
            Console.WriteLine($"REQUEST -> Url: {url}");
            return true;
        }

        private static bool OnResponse(ref Dictionary<string, string> headers, ref string url, ref string parameters, ref string html)
        {
            Console.WriteLine($"RESPONSE -> Url: {url}");
            return true;
        }

        private static void OnError(string errorMessage, PacketType type, Dictionary<string, string> headers, string url)
        {
            Console.WriteLine($"ERROR -> Message: {errorMessage}");
        }

    }
}

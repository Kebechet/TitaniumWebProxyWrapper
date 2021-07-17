using System;
using System.Collections.Generic;
using System.Net;
using TitaniumWebProxyWrapper;

namespace WrapperExample
{
    class Program
    {
        static void Main(string[] args)
        {
            //in PacketSniffer object specify if you want
            //a) IPAddress.Any = global proxy which intercepts all traffic
            //b) IPAddress.Loopback = use this in case another process sends you traffic through localhost and also specify `listenOnPort` parameter
            PacketSniffer ps = new PacketSniffer(IPAddress.Loopback);

            //specify what methods you would like to intercept. Those not used keep NULL
            ps.SetListeningActions(OnRequest,OnResponse,OnError);

            Console.Read();

            //disposing of Proxy resources and disabling PC proxy (without this your internet wont work)
            //manually you can disable this in your Windows proxy setting here: https://i.imgur.com/8HeXZOx.png
            ps.Dispose();
        }


        private static void OnRequest(ref Dictionary<string, string> headers, ref string url, ref string parameters, ref string redirectUrl, ref string cancelRequestHtml)
        {
            //here you can manupulate all OnRequest parameters and these changed values will be used in the request
            Console.WriteLine($"REQUEST -> Url: {url}");
        }

        private static void OnResponse(ref Dictionary<string, string> headers, ref string url, ref string parameters, ref string html)
        {
            //here you can manupulate all OnRequest parameters and these changed values will be used in the response
            Console.WriteLine($"RESPONSE -> Url: {url}");
        }

        private static void OnError(PacketType type, Dictionary<string, string> headers, string url, string errorMessage)
        {
            //in case of error you can log such crashes here
            Console.WriteLine($"ERROR -> Message: {errorMessage}");
        }
    }
}

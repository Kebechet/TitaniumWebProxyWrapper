# Titanium Web Proxy Wrapper

*Tested on:* `Windows 10 19043 x64 with Titanium.Web.Proxy v3.1.1344 + .NET framework 3.8`

This wrapper was created for simplification of work with Titanium web proxy from:

https://github.com/justcoding121/titanium-web-proxy

You can find simple example for global proxy in `example/WrapperExample.sln` 

```c#
using System;
using System.Collections.Generic;
using System.Net;
using TitaniumWebProxyWrapper;

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
```

## To use this wrapper:

1. Download project `TitaniumWebProxyWrapper`
2. In your project click `Solution -> Add -> Existing Project -> and browser to TitaniumWebProxyWrapper project`
3. Then add reference to that project in your main project: `YourProject->right click References->Add Reference->Projects->TitaniumWebProxyWrapper`
4. And at the end just use code from the example above

## TIPS:

a) Your program will show certificate popups. If you don't want to see them just run program (or VisualStudio) as admin.

b) If you have other proxy/VPN running you can experience some problems.






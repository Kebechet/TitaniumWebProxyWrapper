using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Titanium.Web.Proxy;
using Titanium.Web.Proxy.EventArguments;
using Titanium.Web.Proxy.Exceptions;
using Titanium.Web.Proxy.Http;
using Titanium.Web.Proxy.Models;
using Titanium.Web.Proxy.Network;

// Use self-issued generic certificate on all https requests
// Optimizes performance by not creating a certificate for each https-enabled domain
// Useful when certificate trust is not required by proxy clients
// GenericCertificate = new X509Certificate2(Path.Combine(System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "genericcert.pfx"), "password")

//-Proxy is asynchronously multi-threaded, so request/response handlers will be fired as soon as we receive data from client/server asynchronously.This won't be in order necessarily.
//To store data specific to a request/response sequence, one can use SessionEventArgs.UserData property.

//https://github.com/justcoding121/Titanium-Web-Proxy

namespace TitaniumWebProxyWrapper
{
    public class PacketSniffer
    {
        public delegate bool RequestDelegate(ref Dictionary<string, string> headers, ref string url, ref string parameters, out bool abortRequest, ref string redirectUrl, ref string cancelRequestHtml);
        public delegate bool ResponseDelegate(ref Dictionary<string, string> headers, ref string url, ref string parameters, ref string html);
        public delegate void ErrorDelegate(string errorMessage, PacketType type, Dictionary<string, string> headers, string url);

        //private static readonly string pathDesktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        //private static readonly string pathTmp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        //private static readonly string CertFolder = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData); // it is Secured directory ! so Avast Ransomware shield is protecting it
        private static readonly string _certFolder = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        private readonly ProxyServer _proxyServer;
        private const string CERT_PFX_FILE_NAME = "Scertificate.pfx";
        private const string CERT_PFX_PASS = "ScertPassword";
        private static string _certFolderTemp = _certFolder;
        public static string CertPfxPath => $@"{_certFolderTemp}\{CERT_PFX_FILE_NAME}";

        public bool IgnoreImages = false;
        public bool IgnoreJavaScriptRequests = false;
        public bool IgnoreCss = false;
        public int ProxyPort = 0;
        
        private RequestDelegate OnRequestAction = null;
        private ResponseDelegate OnResponseAction = null;
        private ErrorDelegate OnErrorAction = null;
        private readonly object _requestNumberLock = new object();
        private long _requestNumber = 0;
        private long _numberInProgress = 0;
        private bool _isGlobalProxy = false;
        //private int responseRecheckActiveNumberMs = 10;//ms

        public PacketSniffer(IPAddress ip = null, int port = 0, bool persistCertificate = true, bool ignoreImages = false, bool ignoreJavaScriptRequests = false, bool ignoreCss = false)
        {
            IgnoreImages = ignoreImages;
            IgnoreJavaScriptRequests = ignoreJavaScriptRequests;
            IgnoreCss = ignoreCss;

            _proxyServer = new ProxyServer(true, true, true);

            //X509Certificate2 loadedCertificate = LoadCertificate();
            //if (loadedCertificate != null) _proxyServer.CertificateManager.RootCertificate = loadedCertificate;

            // optionally set the Certificate Engine
            _proxyServer.CertificateManager.CertificateEngine = CertificateEngine.BouncyCastleFast;
            _proxyServer.CertificateManager.RootCertificateIssuerName = "CN=S-bot";
            _proxyServer.CertificateManager.RootCertificateName = "S-bot";
            _proxyServer.CertificateManager.StorageFlag = X509KeyStorageFlags.Exportable;
            //_proxyServer.CertificateManager.PfxFilePath = CERT_FILE_NAME;
            //_proxyServer.CertificateManager.RootCertificate = LoadOrMakeCert(persistCertificate);
            //_proxyServer.CertificateManager.PfxFilePath = CertPfxPath;
            //_proxyServer.CertificateManager.PfxPassword = CERT_PFX_PASS;
            _proxyServer.CertificateManager.OverwritePfxFile = true;
            _proxyServer.EnableConnectionPool = true; //test
            _proxyServer.ReuseSocket = true; //test
            //ProxyServer.SupportedSslProtocols = SslProtocols.Ssl2 | SslProtocols.Ssl3 | SslProtocols.Tls | SslProtocols.Tls11 | SslProtocols.Tls12; //ssl are outdated
            _proxyServer.SupportedSslProtocols = SslProtocols.Tls | SslProtocols.Tls11 | SslProtocols.Tls12;

            //ProxyServer.ThreadPoolWorkerThread = 10;
            //ProxyServer.ThreadPoolWorkerThread = Environment.ProcessorCount * 6;
            //ProxyServer.BufferPool.BufferSize = 10;
            _proxyServer.MaxCachedConnections = 200;
            _proxyServer.EnableHttp2=true;
            _proxyServer.CheckCertificateRevocation = X509RevocationMode.NoCheck;

            _proxyServer.ConnectionTimeOutSeconds = 3; //testing, default=60s
            _proxyServer.ConnectTimeOutSeconds = 3;//testing, default=20s
            _proxyServer.TcpTimeWaitSeconds = 3;//testing, default=30s
            //Debug.WriteLine("ProxyServer.ConnectTimeOutSeconds" + ProxyServer.ConnectTimeOutSeconds);
            //Debug.WriteLine("ProxyServer.TcpTimeWaitSeconds" + ProxyServer.TcpTimeWaitSeconds);
            //var c = ProxyServer.ClientConnectionCount;
            //var d = ProxyServer.Enable100ContinueBehaviour;
            ////var e = ProxyServer.EnableConnectionPool;
            //var g = ProxyServer.EnableTcpServerConnectionPrefetch;
            //var i = ProxyServer.ServerConnectionCount;
            _proxyServer.ExceptionFunc = exception =>
            {                
                //handled errors:
                //Error occured whilst handling session request: Authentication failed because the remote party has closed the transport stream.
                //takze chyba pocas requestu...tym padom ziadny response...a tym padom strateny request !

                //from testing
                //Error occured whilst handling session request: Authentication failed because the remote party has closed the transport stream.
                //More than 5 sec exceeded !_newerRequestWaitsForWorker5s

                Task.Run(delegate
                {
                    if (exception is ProxyHttpException phex)
                    {
                        Debug.WriteLine(exception.Message + ": " + phex.InnerException?.Message); //if (phex?.InnerException?.Message == "Authentication failed because the remote party has closed the transport stream.")

                        PacketType packetType = PacketType.Unknown;
                        if (phex.Message.ToLower().Contains("request")) packetType = PacketType.Request;
                        else if (phex.Message.ToLower().Contains("response")) packetType = PacketType.Response;

                        string reqUrl = phex?.Session?.HttpClient?.Request?.Url;
                        string reqMethod = phex?.Session?.HttpClient?.Request?.Method;
                        HeaderCollection reqHeaders = phex?.Session?.HttpClient?.Request?.Headers;//string ReqHeaders = phex.Session.HttpClient.Request.HeaderText;//hlavicky+cookies
                        if (OnErrorAction != null) OnErrorAction(exception.Message + ": " + phex.InnerException?.Message, packetType, HeadersToDictionary(reqHeaders), reqUrl);

                        return;
                    }
                    else
                    {
                        //Couldn't authenticate host 'www.googletagmanager.com' with certificate '*.googletagmanager.com'.
                        Debug.WriteLine("Generic exception in Titanium: " + exception.Message);
                    }
                }).ContinueWith((t) =>
                {
                    if (t.IsFaulted) throw t?.Exception ?? new Exception("MyProxyServer.ExceptionFunc");
                });
            };


            //events
            _proxyServer.BeforeRequest += OnRequest;
            _proxyServer.BeforeResponse += OnResponse;
            //ProxyServer.ServerCertificateValidationCallback += OnCertificateValidation;
            //ProxyServer.ClientCertificateSelectionCallback += OnCertificateSelection;

            if(File.Exists(CertPfxPath)) _proxyServer.CertificateManager.LoadRootCertificate(CertPfxPath, CERT_PFX_PASS, true, X509KeyStorageFlags.Exportable);

            var explicitEndPoint = new ExplicitProxyEndPoint(ip ?? IPAddress.Any, port == 0 ? GetFreeTcpPort() : 8000, true);
            ProxyPort = explicitEndPoint.Port;

            Debug.WriteLine($"Titanium is listening on {explicitEndPoint.IpAddress}:{explicitEndPoint.Port}");

            // Fired when a CONNECT request is received
            //explicitEndPoint.BeforeTunnelConnect += OnBeforeTunnelConnect;

            // An explicit endpoint is where the client knows about the existence of a proxy
            // So client sends request in a proxy friendly manner
            _proxyServer.AddEndPoint(explicitEndPoint);
            _proxyServer.Start(); //here is cert created

            // Transparent endpoint is useful for reverse proxy (client is not aware of the existence of proxy)
            // A transparent endpoint usually requires a network router port forwarding HTTP(S) packets or DNS
            // to send data to this endPoint
            //var transparentEndPoint = new TransparentProxyEndPoint(IPAddress.Any, 8001, true)
            //{
            //    // Generic Certificate hostname to use
            //    // when SNI is disabled by client
            //    GenericCertificateName = "google.com"
            //};

            //ProxyServer.AddEndPoint(transparentEndPoint);

            //ProxyServer.UpStreamHttpProxy = new ExternalProxy() { HostName = "localhost", ProxyPort = 8888 };
            //ProxyServer.UpStreamHttpsProxy = new ExternalProxy() { HostName = "localhost", ProxyPort = 8888 };

            //foreach (var endPoint in ProxyServer.ProxyEndPoints)
            //Debug.WriteLine($"Listening on '{endPoint.GetType().Name}' endpoint at Ip {endPoint.IpAddress} and port: {endPoint.Port}");

            // Only explicit proxies can be set as system proxy!
            _isGlobalProxy = Equals(ip, IPAddress.Any);
            if (_isGlobalProxy)
            {
                _proxyServer.SetAsSystemHttpProxy(explicitEndPoint);
                _proxyServer.SetAsSystemHttpsProxy(explicitEndPoint);
            }

            if (persistCertificate && !File.Exists(CertPfxPath))
            {
                _proxyServer.CertificateManager.RootCertificate.FriendlyName = "S-bot";

               SaveCertificate(_proxyServer.CertificateManager.RootCertificate);
            }
        }

        public void Dispose()
        {
            // Unsubscribe & Quit
            _proxyServer.BeforeRequest -= OnRequest;
            _proxyServer.BeforeResponse -= OnResponse;
            //ProxyServer.ServerCertificateValidationCallback -= OnCertificateValidation;
            //ProxyServer.ClientCertificateSelectionCallback -= OnCertificateSelection;

            _proxyServer.Stop();

            if (_isGlobalProxy)
            {
                _proxyServer.DisableSystemHttpProxy();
                _proxyServer.DisableSystemHttpsProxy();
            }

            _proxyServer.Dispose();
        }

        public X509Certificate2 LoadCertificate(string newLoadPath = "")
        {
            string loadPath = CertPfxPath;

            if (newLoadPath != "") loadPath = newLoadPath;

            if (!File.Exists(loadPath)) return null;

            return new X509Certificate2(CertPfxPath, CERT_PFX_PASS);
        }

        public void SaveCertificate(X509Certificate2 cert, string newSavePath = "")
        {
            if(cert == null) return;
            
            string saveFolder = CertPfxPath;

            if (newSavePath != "") saveFolder = newSavePath;

            File.WriteAllBytes(saveFolder, cert.Export(X509ContentType.Pfx, CERT_PFX_PASS));
        }
        public bool CertFileExists()
        {
            return File.Exists(_certFolderTemp + CertPfxPath);
        }
        public static int GetFreeTcpPort()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }

        //events
        public void SetListeningActions(RequestDelegate onRequest = null, ResponseDelegate onResponse = null, ErrorDelegate onError = null)
        {
            OnRequestAction = onRequest;
            OnResponseAction = onResponse;
            OnErrorAction = onError;
        }
        public async Task OnRequest(object sender, SessionEventArgs e)
        {
            lock (_requestNumberLock)
            {
                e.UserData = _requestNumber;
                _requestNumber++;
            }

            if (IgnoreImages && (e?.HttpClient?.Request?.ContentType?.Contains("image/") ?? false)) return;
            if (IgnoreJavaScriptRequests && (e?.HttpClient?.Request?.ContentType?.Contains("javascript") ?? false)) return;

            var method = e?.HttpClient?.Request?.Method?.ToUpper();
            if (method == "GET" || method == "POST" || method == "PUT" || method == "PATCH")
            {
                string url = e?.HttpClient?.Request?.Url;
                string parameters = (e?.HttpClient?.Request?.HasBody ?? false) ? await e.GetRequestBodyAsString() : "";
                string redirectUrl = String.Empty;
                string cancelRequestHtml = String.Empty;// To cancel a request with a custom HTML content
                HeaderCollection requestHeaders = e?.HttpClient?.Request?.Headers;

                if (OnRequestAction == null) return;

                var headers = HeadersToDictionary(requestHeaders);

                bool wasSomethingChanged = OnRequestAction(ref headers, ref url, ref parameters,out bool abortRequest, ref redirectUrl, ref cancelRequestHtml);//headers,url,parameters,html,
                if (wasSomethingChanged)
                {
                    if (redirectUrl != String.Empty) e.Redirect(redirectUrl);
                    if (cancelRequestHtml != String.Empty) e.Ok(cancelRequestHtml);
                    if (redirectUrl != String.Empty || cancelRequestHtml != String.Empty) return;

                    //set
                    e?.HttpClient?.Request?.Headers?.Clear();
                    e?.HttpClient?.Request?.Headers?.AddHeaders(headers);
                    if(e?.HttpClient?.Request?.Url != null) e.HttpClient.Request.Url = url;
                    if(e?.HttpClient?.Request?.HasBody ?? false) await Task.Run(() => e.SetRequestBodyString(parameters));
                }
            }
        }
        public async Task OnResponse(object sender, SessionEventArgs e)
        {
            ////synchronization of received data
            //Stopwatch sw = new Stopwatch(); sw.Restart();
            //while (((long) e.UserData) != numberInProgress)
            //{
            //    await Task.Delay(responseRecheckActiveNumberMs);
            //    if (sw.Elapsed.TotalSeconds > 4)
            //    {
            //        string msg = "More than 5 sec exceeded !";

            //        if ((long)e.UserData < numberInProgress) msg += "_responseOutdated5s";//response je uz outdated
            //        else
            //        {
            //            msg += "_newerRequestWaitsForWorker5s";
            //        }
            //        Debug.WriteLine(msg);

            //        //string datetime = DateTime.Now.ToString("yy-MM-dd,HH-mm-ss");
            //        //File.WriteAllText(Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + "\\" + datetime + "_response.txt", msg + "\n");

            //        if ((long)e.UserData < numberInProgress) return;//outdated Response--maybe also OnError ?

            //        numberInProgress++;
            //        sw.Restart();
            //    }
            //}
            //Debug.WriteLine("=> ProceedResponse: "+(long)e.UserData);

            int statusCode = e?.HttpClient?.Response?.StatusCode ?? 0;
            string statusDescription = e?.HttpClient?.Response?.StatusDescription;

            if (OnResponseAction == null ||
                IgnoreImages && (e?.HttpClient?.Response?.ContentType?.Contains("image/") ?? false) ||
                IgnoreJavaScriptRequests && (e?.HttpClient?.Response?.ContentType?.Contains("javascript") ?? false) ||  //Content-Type: application/x-javascript
                IgnoreCss && (e?.HttpClient?.Response?.ContentType?.Contains("text/css") ?? false)
                )
            {
                _numberInProgress++;
                return;
            }

            //Stopwatch sw= new Stopwatch(); sw.Restart();
            var method = e?.HttpClient?.Request?.Method?.ToUpper();
            if (method == "GET" || method == "POST")
            {
                //Debug.WriteLine("TitaniumStatusCode: " + e.HttpClient.Response.StatusCode);

                HeaderCollection requestHeaders = e?.HttpClient?.Response?.Headers;
                var headers = HeadersToDictionary(requestHeaders);
                string url = e.HttpClient.Request.Url;
                string parameters = e.HttpClient.Request.HasBody ? await e.GetRequestBodyAsString() : "";
                string html = (e?.HttpClient?.Response?.HasBody ?? false) ? await e.GetResponseBodyAsString() : "";

                bool wasSomethingChanged = OnResponseAction(ref headers, ref url, ref parameters, ref html);//headers,url,parameters,html,
                if (wasSomethingChanged)
                {
                    //set
                    e?.HttpClient?.Response?.Headers?.Clear();
                    e?.HttpClient?.Response?.Headers?.AddHeaders(headers);
                    if(e?.HttpClient?.Request?.Url != null) e.HttpClient.Request.Url = url;
                    if(e?.HttpClient?.Response?.HasBody ?? false) await Task.Run(() => e.SetResponseBodyString(html));
                }

                //if (sw.Elapsed.TotalMilliseconds > 10)//in case parsing will take a lot of time--log it
                //{
                //    string extraInfo = sw.Elapsed.TotalMilliseconds > 200 ? url + ", " + parameters : String.Empty;
                //    Debug.WriteLine($"Response:{sw.Elapsed.TotalMilliseconds:F0}, {extraInfo}");
                //}
            }

            _numberInProgress++;
        }

        //help functions
        private Dictionary<string, string> HeadersToDictionary(HeaderCollection requestHeaders)
        {
            Dictionary<string, string> headers= new Dictionary<string, string>();

            if (requestHeaders != null)
            {
                foreach (HttpHeader rh in requestHeaders)
                {
                    if (!headers.ContainsKey(rh.Name)) headers.Add(rh.Name, rh.Value);
                }
            }

            return headers;
        }
    }
}










//private static bool TrustRootCert(X509Certificate2 cert)
//{
////Local machine doesnt require permission of user !! - CurrentUser shows popup
//bool ret = true;
//X509Store certStore = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
//certStore.Open(OpenFlags.ReadWrite);
//try
//{
//    //certStore.Add(CertMaker.GetRootCertificate());
//    certStore.Add(cert);
//}
//catch
//{
//    ret = false;
//}
//finally
//{
//    certStore.Close();
//}

//return ret;
//}
//public static X509Certificate2 MakeAndSaveCert(bool certOverride = false, bool save = true, string saveFolder = "")
//{
//    var ecdsa = ECDsa.Create(); // generate asymmetric key pair
//    var req = new CertificateRequest("CN=S-bot", ecdsa, HashAlgorithmName.SHA256);
//    X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(20));
//    //TrustRootCert(cert);

//    if (save)
//    {
//        if (saveFolder != "") _certFolderTemp = saveFolder;
//        if (Directory.Exists(saveFolder)) Directory.CreateDirectory(saveFolder);

//        if (certOverride || !File.Exists(CertPfxPath))
//        {
//            // Create PFX (PKCS #12) with private key
//            File.WriteAllBytes(CertPfxPath, cert.Export(X509ContentType.Pfx, CERT_PFX_PASS));
//        }
//    }

//    return cert;
//}













//var headers = requestHeaders.ToDictionary(header => header.Name, header => header.Value);
//List<HttpHeader> headers = requestHeaders.ToList();
//string headers = e.HttpClient.Request.HeaderText;



//private async Task OnBeforeTunnelConnectRequest(object sender, TunnelConnectSessionEventArgs e)
//{
//    string hostname = e.HttpClient.Request.RequestUri.Host;

//    if (hostname.Contains("dropbox.com"))
//    {
//        // Exclude Https addresses you don't want to proxy
//        // Useful for clients that use certificate pinning
//        // for example dropbox.com
//        e.DecryptSsl = false;
//    }
//}

//public static async Task OnRequest(object sender, SessionEventArgs e)
//{
//    Console.WriteLine(e.HttpClient.Request.Url);

//    // read request headers
//    var requestHeaders = e.HttpClient.Request.Headers;

//    var method = e.HttpClient.Request.Method.ToUpper();
//    if ((method == "POST" || method == "PUT" || method == "PATCH"))
//    {
//        // Get/Set request body bytes
//        //byte[] bodyBytes = await e?.GetRequestBody();
//        //await Task.Run(()=> e.SetRequestBody(bodyBytes));

//        // Get/Set request body as string
//        string bodyString = await e.GetRequestBodyAsString();
//        //await Task.Run(() => e.SetRequestBodyString(bodyString));

//        // store request 
//        // so that you can find it from response handler 
//        e.UserData = e.HttpClient.Request;
//    }

//    // To cancel a request with a custom HTML content
//    // Filter URL
//    if (e.HttpClient.Request.RequestUri.AbsoluteUri.Contains("google.com"))
//    {
//        e.Ok("<!DOCTYPE html>" +
//            "<html><body><h1>" +
//            "Website Blocked" +
//            "</h1>" +
//            "<p>Blocked by titanium web proxy.</p>" +
//            "</body>" +
//            "</html>");
//    }

//    // Redirect example
//    if (e.HttpClient.Request.RequestUri.AbsoluteUri.Contains("wikipedia.org"))
//    {
//        e.Redirect("https://www.paypal.com");
//    }
//}

//// Modify response
//public static async Task OnResponse(object sender, SessionEventArgs e)
//{
//    // read response headers
//    var responseHeaders = e.HttpClient.Response.Headers;

//    //if (!e.ProxySession.Request.Host.Equals("medeczane.sgk.gov.tr")) return;
//    if (e.HttpClient.Request.Method == "GET" || e.HttpClient.Request.Method == "POST")
//    {
//        //if (e.HttpClient.Response.StatusCode == 200)
//        //{
//        //    if (e.HttpClient.Response.ContentType != null && e.HttpClient.Response.ContentType.Trim().ToLower().Contains("text/html"))
//        //    {
//        //        byte[] bodyBytes = await e.GetResponseBody();
//        //        await Task.Run(()=> e.SetResponseBody(bodyBytes));

//        //        string body = await e.GetResponseBodyAsString();
//        //        await Task.Run(() => e.SetResponseBodyString(body));
//        //    }
//        //}

//        var a = e.GetResponseBodyAsString();
//        Console.WriteLine(a);
//    }

//    if (e.UserData != null)
//    {
//        // access request from UserData property where we stored it in RequestHandler
//        var request = (Request)e.UserData;
//    }
//}

//// Allows overriding default certificate validation logic
//public static Task OnCertificateValidation(object sender, CertificateValidationEventArgs e)
//{
//    // set IsValid to true/false based on Certificate Errors
//    if (e.SslPolicyErrors == System.Net.Security.SslPolicyErrors.None)
//        e.IsValid = true;

//    return Task.CompletedTask;
//}

//// Allows overriding default client certificate selection logic during mutual authentication
//public static Task OnCertificateSelection(object sender, CertificateSelectionEventArgs e)
//{
//    // set e.clientCertificate to override
//    return Task.CompletedTask;
//}

//my old handling exceptions:
//                    if (phex.Message.ToLower().Contains("request")) //for all bad requests !
//                    {
//                        string reqUrl = phex.Session.HttpClient.Request.Url;
//string reqMethod = phex.Session.HttpClient.Request.Method;
//HeaderCollection reqHeaders = phex.Session.HttpClient.Request.Headers;//string ReqHeaders = phex.Session.HttpClient.Request.HeaderText;//hlavicky+cookies
//                        if (OnErrorAction != null) OnErrorAction(PacketType.Request, HeadersToDictionary(reqHeaders), reqUrl);
//                        //string datetime = DateTime.Now.ToString("yy-MM-dd,HH-mm-ss");
//                        //File.WriteAllText(Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + "\\" + datetime + ".txt", reqUrl + "\n");

//                        return;
//                    }
//                    else if (phex.Message.ToLower().Contains("response"))//only response error handling
//                    {
//                        string reqUrl = phex.Session.HttpClient.Request.Url;
//string StatusDescription = phex.Session.HttpClient.Response.StatusDescription; Debug.WriteLine("ProxyServer.ExceptionFunc -> StatusDescr: " + StatusDescription);
//                        HeaderCollection reqHeaders = phex.Session.HttpClient.Response.Headers;
//                        if (OnErrorAction != null) OnErrorAction(PacketType.Response, HeadersToDictionary(reqHeaders), reqUrl);
//                    }
//                    else /*if (phex.Message.ToLower().Contains("aborted"))*/
//                    {
//                        string reqUrl = phex.Session.HttpClient.Request.Url;
//string StatusDescription = phex.Session.HttpClient.Response.StatusDescription; Debug.WriteLine("ProxyServer.ExceptionFunc -> StatusDescr: " + StatusDescription);
//                        HeaderCollection reqHeaders = phex.Session.HttpClient.Response.Headers;
//                        if (OnErrorAction != null) OnErrorAction(PacketType.Unknown, HeadersToDictionary(reqHeaders), reqUrl);
//                    }
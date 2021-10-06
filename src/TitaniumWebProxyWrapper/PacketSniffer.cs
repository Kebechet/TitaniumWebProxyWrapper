using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Titanium.Web.Proxy;
using Titanium.Web.Proxy.EventArguments;
using Titanium.Web.Proxy.Exceptions;
using Titanium.Web.Proxy.Http;
using Titanium.Web.Proxy.Models;
using Titanium.Web.Proxy.Network;

//Proxy is asynchronously multi-threaded, so request/response handlers will be fired as soon as we receive data from client/server asynchronously.This won't be in order necessarily.
//To store data specific to a request/response sequence, one can use SessionEventArgs.UserData property.
//https://github.com/justcoding121/Titanium-Web-Proxy

namespace TitaniumWebProxyWrapper
{
    public class PacketSniffer
    {
        public delegate void RequestDelegate(ref Dictionary<string, string> headers, ref string url, ref string parameters, ref string redirectUrl, ref string cancelRequestHtml);
        public delegate void ResponseDelegate(ref Dictionary<string, string> headers, ref string url, ref string parameters, ref string html);
        public delegate void ErrorDelegate(PacketType type, Dictionary<string, string> headers, string url, string errorMessage);

        private readonly ProxyServer _proxyServer;
        //private static readonly string _certFolder = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData); // it is Secured directory ! so Avast Ransomware shield is protecting it
        //private static readonly string _certFolder = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        private static readonly string _certFolder = Path.GetDirectoryName(Assembly.GetEntryAssembly().Location);
        private const string CERT_PFX_FILE_NAME = "sCertificate.pfx";
        private const string CERT_PFX_PASS = "sCertPassword";
        public static string CertPfxPath => $@"{_certFolder}\{CERT_PFX_FILE_NAME}";

        public bool IgnoreImages = false;
        public bool IgnoreJavaScriptRequests = false;
        public bool IgnoreCss = false;
        public int ProxyPort = 0;
        
        private RequestDelegate OnRequestAction = null;
        private ResponseDelegate OnResponseAction = null;
        private ErrorDelegate OnErrorAction = null;
        private bool _isGlobalProxy = false;

        public PacketSniffer(IPAddress listeningOnIp = null, int listeningOnPort = 0, bool persistCertificate = true, bool ignoreImages = false, bool ignoreJavaScriptRequests = false, bool ignoreCss = false)
        {
            IgnoreImages = ignoreImages;
            IgnoreJavaScriptRequests = ignoreJavaScriptRequests;
            IgnoreCss = ignoreCss;

            _proxyServer = new ProxyServer(true, true, true);

            // optionally set the Certificate Engine
            _proxyServer.CertificateManager.CertificateEngine = CertificateEngine.BouncyCastleFast;
            _proxyServer.CertificateManager.RootCertificateIssuerName = "CN=Sniffer";
            _proxyServer.CertificateManager.RootCertificateName = "Sniffer";
            _proxyServer.CertificateManager.StorageFlag = X509KeyStorageFlags.Exportable;
            //_proxyServer.CertificateManager.PfxFilePath = CERT_FILE_NAME;
            //_proxyServer.CertificateManager.RootCertificate = LoadOrMakeCert(persistCertificate);
            //_proxyServer.CertificateManager.PfxFilePath = CertPfxPath;
            //_proxyServer.CertificateManager.PfxPassword = CERT_PFX_PASS;
            _proxyServer.CertificateManager.OverwritePfxFile = true;
            _proxyServer.EnableConnectionPool = true; //test
            _proxyServer.ReuseSocket = true; //test
            //_proxyServer.SupportedSslProtocols = SslProtocols.Ssl2 | SslProtocols.Ssl3 | SslProtocols.Tls | SslProtocols.Tls11 | SslProtocols.Tls12; //ssl are outdated
            _proxyServer.SupportedSslProtocols = SslProtocols.Tls | SslProtocols.Tls11 | SslProtocols.Tls12;

            _proxyServer.MaxCachedConnections = 200;
            _proxyServer.EnableHttp2=true;
            _proxyServer.CheckCertificateRevocation = X509RevocationMode.NoCheck;

            _proxyServer.ConnectionTimeOutSeconds = 3; //testing, default=60s
            _proxyServer.ConnectTimeOutSeconds = 3;//testing, default=20s
            _proxyServer.TcpTimeWaitSeconds = 3;//testing, default=30s
            
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
                    if (exception is ProxyHttpException proxyHttpException)
                    {
                        Debug.WriteLine(exception.Message + ": " + proxyHttpException.InnerException?.Message); //if (phex?.InnerException?.Message == "Authentication failed because the remote party has closed the transport stream.")

                        PacketType packetType = PacketType.Unknown;
                        if (proxyHttpException.Message.ToLower().Contains("request")) packetType = PacketType.Request;
                        else if (proxyHttpException.Message.ToLower().Contains("response")) packetType = PacketType.Response;

                        string reqUrl = proxyHttpException?.Session?.HttpClient?.Request?.Url;
                        string reqMethod = proxyHttpException?.Session?.HttpClient?.Request?.Method;
                        HeaderCollection reqHeaders = proxyHttpException?.Session?.HttpClient?.Request?.Headers;//string ReqHeaders = phex.Session.HttpClient.Request.HeaderText;//hlavicky+cookies
                        if (OnErrorAction != null) OnErrorAction(packetType, HeadersToDictionary(reqHeaders), reqUrl, $"{exception.Message}: {proxyHttpException.InnerException?.Message}");

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

            if (File.Exists(CertPfxPath))
            {
                _proxyServer.CertificateManager.LoadRootCertificate(CertPfxPath, CERT_PFX_PASS, true, X509KeyStorageFlags.Exportable);
            }

            var explicitEndPoint = new ExplicitProxyEndPoint(listeningOnIp ?? IPAddress.Any, listeningOnPort == 0 ? GetFreeTcpPort() : 8000, true);
            ProxyPort = explicitEndPoint.Port;

            Debug.WriteLine($"Titanium is listening on {explicitEndPoint.IpAddress}:{explicitEndPoint.Port}");

            // An explicit endpoint is where the client knows about the existence of a proxy
            // So client sends request in a proxy friendly manner
            _proxyServer.AddEndPoint(explicitEndPoint);
            _proxyServer.Start(); //here is cert created

            // Fired when a CONNECT request is received
            //explicitEndPoint.BeforeTunnelConnect += OnBeforeTunnelConnect;

            // Only explicit proxies can be set as system proxy!
            _isGlobalProxy = Equals(listeningOnIp, IPAddress.Any);
            if (_isGlobalProxy)
            {
                _proxyServer.SetAsSystemHttpProxy(explicitEndPoint);
                _proxyServer.SetAsSystemHttpsProxy(explicitEndPoint);
            }

            // Persist cert
            if (!persistCertificate || File.Exists(CertPfxPath)) return;
            if (_proxyServer?.CertificateManager?.RootCertificate?.FriendlyName != null)
            {
                _proxyServer.CertificateManager.RootCertificate.FriendlyName = "S-cert";
            }
            SaveCertificate(_proxyServer.CertificateManager.RootCertificate);
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

        // certificate operations
        public bool CertFileExists() => File.Exists(_certFolder + CertPfxPath);
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

        //event-related
        public void SetListeningActions(RequestDelegate onRequest = null, ResponseDelegate onResponse = null, ErrorDelegate onError = null)
        {
            OnRequestAction = onRequest;
            OnResponseAction = onResponse;
            OnErrorAction = onError;
        }
        public async Task OnRequest(object sender, SessionEventArgs e)
        {
            bool isRequestImage = IgnoreImages && (e?.HttpClient.Request.ContentType?.Contains("image/") ?? false);
            bool isRequestJavaScript = IgnoreJavaScriptRequests && (e?.HttpClient.Request.ContentType?.Contains("javascript") ?? false); //Content-Type: application/x-javascript
            bool isRequestCss = IgnoreCss && (e?.HttpClient.Request.ContentType?.Contains("text/css") ?? false);
            e.UserData = e.HttpClient.Request.HasBody ? await e.GetRequestBodyAsString() : null;
            if (OnRequestAction == null || isRequestImage || isRequestJavaScript || isRequestCss) return;

            var method = e?.HttpClient.Request.Method.ToUpper();
            if (method == "GET" || method == "POST" || method == "PUT" || method == "PATCH")
            {
                string url = e.HttpClient.Request.Url;
                string parameters = e.HttpClient.Request.HasBody ? await e.GetRequestBodyAsString() : string.Empty;
                string redirectUrl = string.Empty;
                string cancelRequestHtml = string.Empty; //To cancel a request with a custom HTML content
                HeaderCollection requestHeaders = e.HttpClient.Request.Headers;
                var headers = HeadersToDictionary(requestHeaders);

                PacketData packetData = new PacketData(headers, url, parameters, redirectUrl, cancelRequestHtml);
                OnRequestAction(ref headers, ref url, ref parameters, ref redirectUrl, ref cancelRequestHtml); //headers,url,parameters,html,
                packetData.SetNewValues(headers, url, parameters, redirectUrl, cancelRequestHtml);
                e.UserData = parameters;

                if (packetData.IsUrlChanged)
                {
                    e.HttpClient.Request.Url = url;
                }
                if (packetData.AreParametersChanged && e.HttpClient.Request.HasBody) // maybe delete HasBody condition
                {
                    await Task.Run(() => e.SetRequestBodyString(parameters));
                }
                if (packetData.AreHeadersChanged)
                {
                    e.HttpClient.Request.Headers.Clear();
                    e.HttpClient.Request.Headers.AddHeaders(headers);
                }
                if (packetData.IsRedirectUrlChanged)
                {
                    e.Redirect(redirectUrl); // is maybe same as changing URL
                }
                if (packetData.IsCancelRequestHtmlChanged)
                {
                    e.Ok(cancelRequestHtml);
                }
            }
        }
        public async Task OnResponse(object sender, SessionEventArgs e)
        {
            bool isResponseImage = IgnoreImages && (e?.HttpClient.Response.ContentType?.Contains("image/") ?? false);
            bool isResponseJavaScript = IgnoreJavaScriptRequests && (e?.HttpClient.Response.ContentType?.Contains("javascript") ?? false); //Content-Type: application/x-javascript
            bool isResponseCss = IgnoreCss && (e?.HttpClient.Response.ContentType?.Contains("text/css") ?? false);
            if (OnResponseAction == null || isResponseImage || isResponseJavaScript || isResponseCss) return;

            var method = e?.HttpClient.Request.Method.ToUpper();
            if (method == "GET" || method == "POST" || method == "PUT" || method == "PATCH")
            {
                string url = e.HttpClient.Request.Url;
                string parameters = (string)(e.UserData ?? string.Empty);
                string html = e.HttpClient.Response.HasBody ? await e.GetResponseBodyAsString() : "";
                HeaderCollection requestHeaders = e.HttpClient.Response.Headers;
                var headers = HeadersToDictionary(requestHeaders);

                PacketData packetData = new PacketData(headers, url, parameters, html:html);
                OnResponseAction(ref headers, ref url, ref parameters, ref html);
                packetData.SetNewValues(headers, url, parameters, html:html);

                if (packetData.IsUrlChanged)
                {
                    e.HttpClient.Request.Url = url;
                }
                if (packetData.AreParametersChanged && (e.HttpClient.Request.HasBody)) // maybe delete HasBody condition
                {
                    await Task.Run(() => e.SetRequestBodyString(parameters));
                }
                if (packetData.AreHeadersChanged)
                {
                    e.HttpClient.Request.Headers.Clear();
                    e.HttpClient.Request.Headers.AddHeaders(headers);
                }
                if (packetData.IsHtmlChanged && e.HttpClient.Response.HasBody)
                {
                    await Task.Run(() => e.SetResponseBodyString(html));
                }
            }
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
        public static int GetFreeTcpPort()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }
    }
}

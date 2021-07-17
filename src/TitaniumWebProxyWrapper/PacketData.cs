using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TitaniumWebProxyWrapper
{
    public class PacketData
    {
        private readonly string _url;
        private string _urlNew;
        private readonly string _parameters;
        private string _parametersNew;
        private readonly string _redirectUrl;
        private string _redirectUrlNew;
        private readonly string _cancelRequestHtml;
        private string _cancelRequestHtmlNew;
        private readonly Dictionary<string, string> _headers;
        private Dictionary<string, string> _headersNew;
        private readonly string _html;
        private string _htmlNew;

        public bool IsUrlChanged => _url.Length != _urlNew.Length || _url != _urlNew;
        public bool AreParametersChanged => _parameters.Length != _parametersNew.Length || _parameters != _parametersNew;
        public bool IsRedirectUrlChanged => _redirectUrl.Length != _redirectUrlNew.Length || _redirectUrl != _redirectUrlNew;
        public bool IsCancelRequestHtmlChanged => _cancelRequestHtml.Length != _cancelRequestHtmlNew.Length || _cancelRequestHtml != _cancelRequestHtmlNew;
        public bool AreHeadersChanged => _headers.Count != _headersNew.Count || _headers.Except(_headersNew).Any();
        public bool IsHtmlChanged => _html.Length != _htmlNew.Length || _html != _htmlNew;


        public PacketData(Dictionary<string, string> headers, string url, string parameters, string redirectUrl= "", string cancelRequestHtml = "", string html = "")
        {
            _headers = _headersNew = headers.ToDictionary(entry => entry.Key,
                entry => entry.Value); ; //dict is ref type
            _url = _urlNew = url;
            _parameters = _parametersNew = parameters;
            _redirectUrl = _redirectUrlNew = redirectUrl;
            _cancelRequestHtml = _cancelRequestHtmlNew = cancelRequestHtml;
            _html = _htmlNew = html;
        }

        public void SetNewValues(Dictionary<string, string> headers, string url, string parameters, string redirectUrl = "", string cancelRequestHtml = "", string html = "")
        {
            _headersNew = headers;
            _urlNew = url;
            _parametersNew = parameters;
            _redirectUrlNew = redirectUrl;
            _cancelRequestHtmlNew = cancelRequestHtml;
            _htmlNew = html;
        }
    }
}

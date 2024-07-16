#include "HttpClient.h"
#include <charconv>
#include <cstring>

//----------------------------------------------------------------------------

static const char hex[256][2] = {{'0','0'},{'0','1'},{'0','2'},{'0','3'},{'0','4'},{'0','5'},{'0','6'},{'0','7'},{'0','8'},{'0','9'},
                                 {'0','A'},{'0','B'},{'0','C'},{'0','D'},{'0','E'},{'0','F'},{'1','0'},{'1','1'},{'1','2'},{'1','3'},
                                 {'1','4'},{'1','5'},{'1','6'},{'1','7'},{'1','8'},{'1','9'},{'1','A'},{'1','B'},{'1','C'},{'1','D'},
                                 {'1','E'},{'1','F'},{'2','0'},{'2','1'},{'2','2'},{'2','3'},{'2','4'},{'2','5'},{'2','6'},{'2','7'},
                                 {'2','8'},{'2','9'},{'2','A'},{'2','B'},{'2','C'},{'2','D'},{'2','E'},{'2','F'},{'3','0'},{'3','1'},
                                 {'3','2'},{'3','3'},{'3','4'},{'3','5'},{'3','6'},{'3','7'},{'3','8'},{'3','9'},{'3','A'},{'3','B'},
                                 {'3','C'},{'3','D'},{'3','E'},{'3','F'},{'4','0'},{'4','1'},{'4','2'},{'4','3'},{'4','4'},{'4','5'},
                                 {'4','6'},{'4','7'},{'4','8'},{'4','9'},{'4','A'},{'4','B'},{'4','C'},{'4','D'},{'4','E'},{'4','F'},
                                 {'5','0'},{'5','1'},{'5','2'},{'5','3'},{'5','4'},{'5','5'},{'5','6'},{'5','7'},{'5','8'},{'5','9'},
                                 {'5','A'},{'5','B'},{'5','C'},{'5','D'},{'5','E'},{'5','F'},{'6','0'},{'6','1'},{'6','2'},{'6','3'},
                                 {'6','4'},{'6','5'},{'6','6'},{'6','7'},{'6','8'},{'6','9'},{'6','A'},{'6','B'},{'6','C'},{'6','D'},
                                 {'6','E'},{'6','F'},{'7','0'},{'7','1'},{'7','2'},{'7','3'},{'7','4'},{'7','5'},{'7','6'},{'7','7'},
                                 {'7','8'},{'7','9'},{'7','A'},{'7','B'},{'7','C'},{'7','D'},{'7','E'},{'7','F'},{'8','0'},{'8','1'},
                                 {'8','2'},{'8','3'},{'8','4'},{'8','5'},{'8','6'},{'8','7'},{'8','8'},{'8','9'},{'8','A'},{'8','B'},
                                 {'8','C'},{'8','D'},{'8','E'},{'8','F'},{'9','0'},{'9','1'},{'9','2'},{'9','3'},{'9','4'},{'9','5'},
                                 {'9','6'},{'9','7'},{'9','8'},{'9','9'},{'9','A'},{'9','B'},{'9','C'},{'9','D'},{'9','E'},{'9','F'},
                                 {'A','0'},{'A','1'},{'A','2'},{'A','3'},{'A','4'},{'A','5'},{'A','6'},{'A','7'},{'A','8'},{'A','9'},
                                 {'A','A'},{'A','B'},{'A','C'},{'A','D'},{'A','E'},{'A','F'},{'B','0'},{'B','1'},{'B','2'},{'B','3'},
                                 {'B','4'},{'B','5'},{'B','6'},{'B','7'},{'B','8'},{'B','9'},{'B','A'},{'B','B'},{'B','C'},{'B','D'},
                                 {'B','E'},{'B','F'},{'C','0'},{'C','1'},{'C','2'},{'C','3'},{'C','4'},{'C','5'},{'C','6'},{'C','7'},
                                 {'C','8'},{'C','9'},{'C','A'},{'C','B'},{'C','C'},{'C','D'},{'C','E'},{'C','F'},{'D','0'},{'D','1'},
                                 {'D','2'},{'D','3'},{'D','4'},{'D','5'},{'D','6'},{'D','7'},{'D','8'},{'D','9'},{'D','A'},{'D','B'},
                                 {'D','C'},{'D','D'},{'D','E'},{'D','F'},{'E','0'},{'E','1'},{'E','2'},{'E','3'},{'E','4'},{'E','5'},
                                 {'E','6'},{'E','7'},{'E','8'},{'E','9'},{'E','A'},{'E','B'},{'E','C'},{'E','D'},{'E','E'},{'E','F'},
                                 {'F','0'},{'F','1'},{'F','2'},{'F','3'},{'F','4'},{'F','5'},{'F','6'},{'F','7'},{'F','8'},{'F','9'},
                                 {'F','A'},{'F','B'},{'F','C'},{'F','D'},{'F','E'},{'F','F'}};

static std::string urlPercentEncode(std::string_view view)
{
    std::string ret;
    ret.reserve(view.size() * 3);

    for(char v : view)
    {
        if(v == ' ')
        {
           ret.push_back('+');
           continue;
        }

        if(std::isalnum(v) || v == '-' || v == '_' || v == '.' || v == '~')
        {
           ret.push_back(v);
           continue;
        }

        ret.push_back('%');
        ret.insert(ret.size(), hex[static_cast<unsigned char>(v)], 2);
    }

    ret.shrink_to_fit();
    return ret;
}

//----------------------------------------------------------------------------

static const std::string_view S_get("GET"),
                              S_post("POST"),
                              S_put("PUT"),
                              S_patch("PATCH"),
                              S_delete("DELETE"),
                              S_v1_1("HTTP/1.1\r\n"),
                              S_host("Host: "),
                              S_agent("User-Agent: HttpClient 1.0\r\n"),
                              S_contentLength("Content-Length: "),
                              S_contentLength_S("Content-Length"),
                              S_transferEncoding_S("Transfer-Encoding"),
                              S_contentType_S("Content-Type");

static const std::string_view errorReadingHeader_msg("Error reading header sent from server"),
                              errorReadingData_msg("Error reading data from the server"),
                              incorrectChunkedSize_msg("Incorrect chunked size"),
                              responseCallbakMissing_msg("Response callback missing");

static constexpr int chunkHeaderSize = 8 + 4;

//----------------------------------------------------------------------------

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

class WSAInit final
{
    static const WSAInit wsa;

    WSADATA data;
    const bool init;

    explicit WSAInit():init(WSAStartup(MAKEWORD(2, 2), &data) == 0){}
public:
    ~WSAInit(){ if(init) WSACleanup(); }
    static bool isInit(){ return wsa.init; }
};

const WSAInit WSAInit::wsa = WSAInit();

#endif

#include <openssl/ssl.h>
#include <openssl/err.h>

class OpenSSLInit final
{
    static const OpenSSLInit ossl;

    SSL_CTX * ctx = nullptr;
    std::string err;

    explicit OpenSSLInit()
    {
       const SSL_METHOD * method = TLS_client_method();
       ctx = SSL_CTX_new(method);
       if(ctx == nullptr) err = ERR_error_string(ERR_get_error(), nullptr);
    }
public:
    ~OpenSSLInit(){ if(ctx != nullptr) SSL_CTX_free(ctx); }
    static bool isInit(){ return (ossl.ctx != nullptr); }
    static std::string error(){ return ossl.err; }
    static SSL_CTX * getCTX(){ return ossl.ctx; }
};

const OpenSSLInit OpenSSLInit::ossl = OpenSSLInit();

//----------------------------------------------------------------------------

class ASocket
{
public:
    explicit ASocket(){}
    virtual ~ASocket(){}
    virtual int Read(char * buf, int len) = 0;
    virtual int Write(char * buf, int len) = 0;
    virtual bool isInit(){ return true; }
    virtual std::string error(){ return std::string(); }
};

class Socket final : public ASocket
{
    const int socket;
public:
    explicit Socket(const int socket):socket(socket){}
    ~Socket(){ closesocket(socket); }
    int Read(char * buf, int len) override{ return recv(socket, buf, len, 0); }
    int Write(char * buf, int len) override{ return send(socket, buf, len, 0); }
};

class SSLSocket final : public ASocket
{
    const int socket;
    SSL * ssl = nullptr;
    std::string err;
public:
    explicit SSLSocket(const int socket):socket(socket)
    {
       SSL_CTX * ctx = OpenSSLInit::getCTX();
       if(ctx == nullptr) return;

       ssl = SSL_new(ctx);
       if(ssl == nullptr)
       {
          err = "SSL socket initialization error";
          return;
       }

       SSL_set_fd(ssl, socket);

       const int status = SSL_connect(ssl);

       if(status != 1)
       {
          err = ERR_error_string(SSL_get_error(ssl, status), nullptr);
          SSL_free(ssl);
          ssl = nullptr;
       }
    }

    ~SSLSocket()
    {
       if(ssl != nullptr) SSL_free(ssl);
       closesocket(socket);
    }

    int Read(char * buf, int len) override{ return (ssl != nullptr) ? SSL_read(ssl, buf, len) : -1; }
    int Write(char * buf, int len) override{ return (ssl != nullptr) ? SSL_write(ssl, buf, len) : -1; }
    bool isInit() override { return (ssl != nullptr); }
    std::string error() override { return err; }
};

//----------------------------------------------------------------------------

static std::shared_ptr<ASocket> OpenSocket(std::string_view host, unsigned short port, bool secureLayer, std::string & error)
{
#ifdef WIN32
    if(!WSAInit::isInit())
    {
       error = "WSA initialization error";
       return nullptr;
    }
#endif

    if(secureLayer && !OpenSSLInit::isInit())
    {
       error = "OpenSSL initialization error: " + OpenSSLInit::error();
       return nullptr;
    }

    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo * result = nullptr;
    int res = getaddrinfo(std::string(host).data(), nullptr, &hints, &result);

    if(res != 0)
    {
       error = "Getaddrinfo failed with error: " + std::to_string(res);
       return nullptr;
    }

    int socket = -1;
    for(struct addrinfo * next = result; next != nullptr; next = next->ai_next)
    {
        socket = ::socket(next->ai_family, next->ai_socktype, next->ai_protocol);
        if(socket < 0) continue;

        if(next->ai_family == AF_INET) reinterpret_cast<struct sockaddr_in *>(next->ai_addr)->sin_port = htons(port);
        else reinterpret_cast<struct sockaddr_in6 *>(next->ai_addr)->sin6_port = htons(port);

        res = connect(socket, next->ai_addr, next->ai_addrlen);
        if(res == 0) break;
        closesocket(socket);
        socket = -1;
    }

    freeaddrinfo(result);

    if(socket < 0)
    {
       if(res < 0) error = "Server connection error: " + std::to_string(WSAGetLastError());
       else error = "Connections not found";
       return nullptr;
    }

    if(secureLayer)
    {
       std::shared_ptr<SSLSocket> sslsocket = std::make_shared<SSLSocket>(socket);

       if(!sslsocket->isInit())
       {
          error = "SSL " + sslsocket->error();
          return nullptr;
       }
       else return std::move(sslsocket);
    }
    else return std::make_shared<Socket>(socket);
}

//----------------------------------------------------------------------------

HttpData::HttpData(){}
HttpData::HttpData(const char * data, std::size_t size)
{
    _data.reset(new char[size]);
    _size = size;
    std::memcpy(_data.get(), data, size);
}

HttpData::HttpData(const std::vector<char> & vector):HttpData(vector.data(), vector.size()){}
HttpData::HttpData(const std::string & string):HttpData(string.data(), string.size()){}
HttpData::HttpData(std::string_view string_view):HttpData(string_view.data(), string_view.size()){}
HttpData::HttpData(std::span<char> span):HttpData(span.data(), span.size()){}

std::size_t HttpData::size() const { return _size; }
std::span<char> HttpData::data() const { return std::span(_data.get(), _size); }

std::string_view HttpData::contentType() const
{
    const std::string_view type("application/octet-stream");
    return type;
}

HttpData::Type HttpData::type() const { return Data; }

//=====

std::string FormData::makeData(const std::map<std::string, std::string> & keyValue)
{
    std::string ret;

    for(int i = 0; const auto & pair : keyValue)
    {
        if(i > 0) ret.push_back('&');
        ret += urlPercentEncode(pair.first) + "=" + urlPercentEncode(pair.second);
        i++;
    }

    return ret;
}

FormData::FormData(const std::string & string):HttpData(string){}
FormData::FormData(std::string_view string_view):HttpData(string_view){}
FormData::FormData(const std::map<std::string, std::string> & keyValue):HttpData(makeData(keyValue)){}

std::string_view FormData::contentType() const
{
    const std::string_view type("application/x-www-form-urlencoded");
    return type;
}

HttpData::Type FormData::type() const { return Form; }

//=====

TextData::TextData(std::string & string):HttpData(string){}
TextData::TextData(std::string_view string_view):HttpData(string_view){}

std::string_view TextData::contentType() const
{
    const std::string_view type("text/plain");
    return type;
}

HttpData::Type TextData::type() const { return Text; }

//=====

JsonData::JsonData(std::string & string):HttpData(string){}
JsonData::JsonData(std::string_view string_view):HttpData(string_view){}

std::string_view JsonData::contentType() const
{
    const std::string_view type("application/json");
    return type;
}

HttpData::Type JsonData::type() const { return Json; }

//=====

XmlData::XmlData(std::string & string):HttpData(string){}
XmlData::XmlData(std::string_view string_view):HttpData(string_view){}

std::string_view XmlData::contentType() const
{
    const std::string_view type("application/xml");
    return type;
}

HttpData::Type XmlData::type() const { return Xml; }

//=====

OtherData::OtherData(const std::string & type, const char * data, std::size_t size):HttpData(data, size), _type(type){}
OtherData::OtherData(const std::string & type, std::vector<char> & vector):HttpData(vector), _type(type){}
OtherData::OtherData(const std::string & type, std::string & string):HttpData(string), _type(type){}
OtherData::OtherData(const std::string & type, std::string_view string_view):HttpData(string_view), _type(type){}
OtherData::OtherData(const std::string & type, std::span<char> span):HttpData(span), _type(type){}

std::string_view OtherData::contentType() const
{
    const std::string_view type(_type);
    return type;
}

HttpData::Type OtherData::type() const { return Other; }

//----------------------------------------------------------------------------

HttpRequest::HttpRequest(){}
HttpRequest::HttpRequest(Protocol protocol, HttpMethod method, const std::string & host, unsigned short port, const std::string & path):
_protocol(protocol), _method(method), _port(port), _host(host), _path(path){}

void HttpRequest::setProtocol(Protocol protocol){ _protocol = protocol; }
HttpRequest::Protocol HttpRequest::protocol() const{ return _protocol; }

void HttpRequest::setMethod(HttpMethod method){ _method = method; }
HttpRequest::HttpMethod HttpRequest::method() const { return _method; }

void HttpRequest::setHost(const std::string & host){ _host = host; }
const std::string & HttpRequest::host() const { return _host; }

void HttpRequest::setPort(unsigned short port){ _port = port; }
unsigned short HttpRequest::port() const { return _port; }

void HttpRequest::setPath(const std::string & path){ _path = path; }
const std::string & HttpRequest::path() const { return _path; }

int HttpRequest::queryesCount() const { return _queryes.size(); }
std::string HttpRequest::query(const std::string & key) const { return _queryes[key]; }
const std::map<std::string,std::string> & HttpRequest::queryes() const { return _queryes; }
void HttpRequest::addQuery(const std::string & key, const std::string & value){ _queryes[key] = value; }
void HttpRequest::addQueryes(const std::map<std::string,std::string> & values){ _queryes.insert(values.begin(),values.end()); }
void HttpRequest::setQueryes(const std::map<std::string,std::string> & values){ _queryes = values; }
void HttpRequest::clearQueryes(){ _queryes.clear(); }

void HttpRequest::setFragment(const std::string & fragment){ _fragment = fragment; }
const std::string & HttpRequest::fragment() const{ return _fragment; }

int HttpRequest::headersCount() const { return _headers.size(); }
std::string HttpRequest::header(const std::string & key) const{ return _headers[key]; }
const std::map<std::string,std::string> & HttpRequest::headers() const { return _headers; }
void HttpRequest::addHeader(const std::string & key, const std::string & value){ _headers[key] = value; }
void HttpRequest::addHeaders(const std::map<std::string,std::string> & values){ _headers.insert(values.begin(),values.end()); }
void HttpRequest::setHeaders(const std::map<std::string,std::string> & values){ _headers = values; }
void HttpRequest::clearHeaders(){ _headers.clear(); }

void HttpRequest::setData(const HttpData & data)
{


    switch(data.type())
    {
           case HttpData::Data: _data = std::make_shared<HttpData>(data);
           break;
           case HttpData::Form: _data = std::make_shared<FormData>(static_cast<const FormData &>(data));
           break;
           case HttpData::Text: _data = std::make_shared<TextData>(static_cast<const TextData &>(data));
           break;
           case HttpData::Json: _data = std::make_shared<JsonData>(static_cast<const JsonData &>(data));
           break;
           case HttpData::Xml: _data = std::make_shared<XmlData>(static_cast<const XmlData &>(data));
           break;
           case HttpData::Other: _data = std::make_shared<OtherData>(static_cast<const OtherData &>(data));
           break;
    }

    std::string key(S_contentType_S);

    if(data.size() > 0)
    {
       _dataLength = std::to_string(data.size());
       _headers[key] = data.contentType();
    }
    else if(_headers.contains(key)) _headers.erase(key);
}

HttpData * HttpRequest::data() const { return _data.get(); }

bool HttpRequest::isValid() const { return (!_host.empty() && !_path.empty()); }

long long HttpRequest::calculateSize() const
{
    if(!isValid()) return -1;

    long long calc = 0;

    switch (_method)
    {
      case GET_METHOD: calc += S_get.size();
      break;
      case PUT_METHOD: calc += S_put.size();
      break;
      case POST_METHOD: calc += S_post.size();
      break;
      case PATCH_METHOD: calc += S_patch.size();
      break;
      case DELETE_METHOD: calc += S_delete.size();
      break;
    }

    calc++;
    calc += _path.size();

    for(const auto & v : _queryes)
    {
        calc += v.first.size() + v.second.size() + 2;
    }

    if(_fragment.size())
    {
       calc += _fragment.size();
       calc++;
    }

    calc++;
    calc += S_v1_1.size();
    calc += S_host.size() + _host.size() + 2;
    calc += S_agent.size();

    if(_data && _data->size() > 0) calc += S_contentLength.size() + _dataLength.size() + 2;

    _headers.erase("Host");
    _headers.erase("User-Agent");
    _headers.erase("Content-Length");

    for(const auto & v : _headers) calc += v.first.size() + v.second.size() + 4;

    calc += 2;
    calc += (_data) ? _data->size() : 0;

    return calc;
}

std::vector<char> HttpRequest::make() const
{
    std::vector<char> ret;
    long long calc = calculateSize();

    if(calc < 0) return ret;

    ret.reserve(calc);

    switch (_method)
    {
      case GET_METHOD: ret.insert(ret.end(), S_get.begin(), S_get.end());
      break;
      case PUT_METHOD: ret.insert(ret.end(), S_put.begin(), S_put.end());
      break;
      case POST_METHOD: ret.insert(ret.end(), S_post.begin(), S_post.end());
      break;
      case PATCH_METHOD: ret.insert(ret.end(), S_patch.begin(), S_patch.end());
      break;
      case DELETE_METHOD: ret.insert(ret.end(), S_delete.begin(), S_delete.end());
      break;
    }

    ret.push_back(' ');
    ret.insert(ret.end(), _path.begin(), _path.end());

    unsigned int i = 0;
    for(const auto & v : _queryes)
    {
        if(i == 0) ret.push_back('?'); else ret.push_back('&');
        std::string encode = urlPercentEncode(v.first);
        ret.insert(ret.end(), encode.begin(), encode.end());
        ret.push_back('=');
        encode = urlPercentEncode(v.second);
        ret.insert(ret.end(), encode.begin(), encode.end());
        i++;
    }

    if(_fragment.size() > 0)
    {
       ret.push_back('#');
       std::string encode = urlPercentEncode(_fragment);
       ret.insert(ret.end(), encode.begin(), encode.end());
    }

    ret.push_back(' ');
    ret.insert(ret.end(), S_v1_1.begin(), S_v1_1.end());

    ret.insert(ret.end(), S_host.begin(), S_host.end());
    ret.insert(ret.end(), _host.begin(), _host.end());
    ret.push_back('\r');
    ret.push_back('\n');

    ret.insert(ret.end(), S_agent.begin(), S_agent.end());

    if(_data && _data->size() > 0)
    {
       ret.insert(ret.end(), S_contentLength.begin(), S_contentLength.end());
       ret.insert(ret.end(), _dataLength.begin(), _dataLength.end());
       ret.push_back('\r');
       ret.push_back('\n');
    }

    for(const auto & v : _headers)
    {
        ret.insert(ret.end(), v.first.begin(), v.first.end());
        ret.push_back(':');
        ret.push_back(' ');
        ret.insert(ret.end(), v.second.begin(), v.second.end());
        ret.push_back('\r');
        ret.push_back('\n');
    }

    ret.push_back('\r');
    ret.push_back('\n');

    if(_data && _data->size() > 0)
    {
       std::span<char> data = _data->data();
       ret.insert(ret.end(), data.begin(), data.end());
    }
    return ret;
}

//----------------------------------------------------------------------------

HttpResponse::HttpResponse(){}

int HttpResponse::code() const { return _code; }
int HttpResponse::headersCount() const { return _headers.size(); }
const std::map<std::string_view, std::string_view> & HttpResponse::headers() const { return _headers; }
std::string_view HttpResponse::header(std::string_view key) const { return _headers[key]; }
std::span<char> HttpResponse::data() const{ return _data; }

//----------------------------------------------------------------------------

bool HttpClient::makeRequest(HttpRequest & request, HttpRequest::HttpMethod method, std::string_view url, HttpClient * client, const HttpData & data)
{
    request.setMethod(method);

    std::size_t begin = 0;
    std::string_view host;

    if(url.starts_with("http://"))
    {
       request.setProtocol(HttpRequest::HTTP);
       request.setPort(80);
       begin = 7;
    }
    else if(url.starts_with("https://")) begin = 8;
    else
    {
       auto pos = url.find("://", begin);
       if(pos != std::string_view::npos)
       {
          if(client != nullptr) client->err = "Incorrect url scheme";
          return false;
       }
    }

    auto pos = url.find('/', begin);
    if(pos == std::string_view::npos) host = url.substr(begin, url.size() - begin);
    else
    {
       host = url.substr(begin, pos - begin);
       std::string_view path = url.substr(pos, url.size() - pos);
       request.setPath(std::string(path));
    }

    if(auto pos = host.find(':'); pos != std::string_view::npos)
    {
       std::string_view str = host.substr(pos + 1, host.size() - pos + 1);

       if(str.size() > 0)
       {
          unsigned short port;
          auto [ptr, ec] { std::from_chars(str.begin(),str.end(), port) };

          if(ec != std::errc())
          {
             if(client != nullptr) client->err = "Incorrect port";
             return false;
          }

          request.setPort(port);
       }

       host = host.substr(0, pos);
    }

    if(host.empty())
    {
       if(client != nullptr) client->err = "Missing host";
       return false;
    }

    request.setHost(std::string(host));
    request.addHeader("Connection", "close");
    request.setData(data);

    return true;
}

bool HttpClient::sendUrl(HttpRequest::HttpMethod method, std::string_view url, const std::function<void (const HttpRequest &, const HttpResponse &)> &responseCallback, const HttpData & data)
{
    if(!responseCallback)
    {
       err = responseCallbakMissing_msg;
       return false;
    }

    HttpRequest request;
    if(!makeRequest(request, method, url, this, data)) return false;
    return sendRequest(request, responseCallback);
}

HttpClient::HttpClient(int maxHeaderSize):_maxHeaderSize(maxHeaderSize){}
const std::string & HttpClient::error() const { return err; }

static bool getChuckSize(std::size_t & begin, std::string_view view, std::size_t & size, std::string & error)
{
    auto pos = view.find("\r\n", begin);

    if(pos == std::string_view::npos)
    {
       error = incorrectChunkedSize_msg;
       return false;
    }

    std::string_view sub = view.substr(begin, pos - begin);

    auto [ptr, ec] { std::from_chars(sub.begin(), sub.end(), size, 16) };

    if(ec != std::errc())
    {
       error = std::string(incorrectChunkedSize_msg) + ": " + std::string(sub);
       return false;
    }

    begin += sub.size() + 2;

    return true;
}

bool HttpClient::sendRequest(const HttpRequest & request, const std::function<void (const HttpRequest &, const HttpResponse &)> &responseCallback)
{
    if(!responseCallback)
    {
       err = responseCallbakMissing_msg;
       return false;
    }

    auto data = request.make();

    if(data.empty())
    {
       err = "Http request is invalid";
       return false;
    }

    std::shared_ptr<ASocket> socket = OpenSocket(request.host(), request.port(), request.protocol() == HttpRequest::HTTPS, err);
    if(socket == nullptr) return false;

    std::size_t count = 0;

    while(count != data.size())
    {
          int ret = socket->Write(data.data() + count, data.size() - count);

          if(ret <= 0)
          {
             err = "Error sending data to the server";
             return false;
          }

          count += ret;
    }

    data.clear();

    //--------------------------------------

    std::unique_ptr<char[]> headerData(new char[_maxHeaderSize]);
    count = socket->Read(headerData.get(), _maxHeaderSize);

    if(count <= 0)
    {
       err = errorReadingData_msg;
       return false;
    }

    std::string_view view(headerData.get(), count);

    auto pos = view.find("\r\n");
    if(pos == std::string_view::npos)
    {
       err = errorReadingHeader_msg;
       return false;
    }

    std::string_view sub = view.substr(0, pos);
    auto begin = sub.find(' ');
    if(begin == std::string_view::npos)
    {
       err = errorReadingHeader_msg;
       return false;
    }

    sub = sub.substr(begin + 1, sub.size() - begin);
    if(begin = sub.find(' '); begin != std::string_view::npos) sub = sub.substr(0, begin);

    HttpResponse response;

    {
      auto [ptr, ec] { std::from_chars(sub.begin(), sub.end(), response._code) };

      if(ec != std::errc())
      {
         err = "Incorrect result code";
         return false;
      }
    }

    bool ok = false;

    for(begin = pos + 2; (pos = view.find("\r\n", begin)) != std::string_view::npos;  begin = pos + 2)
    {
        if(begin == pos)
        {
           ok = true;
           break;
        }

        if(pos - begin < 4) break;

        sub = view.substr(begin, pos - begin);
        auto pos = sub.find(':');
        if(pos == std::string_view::npos || pos == 0 || pos == sub.size() - 1) break;

        std::string_view key = sub.substr(0, pos);
        if(key[0] == ' ') break;

        pos++;
        if(sub[pos] != ' ') break;

        pos++;
        if(pos == sub.size()) break;
        response._headers.insert({key, sub.substr(pos, sub.size() - pos)});;
    }

    if(!ok)
    {
       err = errorReadingHeader_msg;
       return false;
    }

    pos += 2;

    if(response._headers.contains(S_contentLength_S))
    {
       std::string_view s_length = response._headers[S_contentLength_S];
       std::size_t length;

       {
         auto [ptr, ec] { std::from_chars(s_length.begin(), s_length.end(), length) };

         if(ec != std::errc())
         {
            err = "Incorrect " + std::string(S_contentLength_S) + " size: " + std::string(s_length);
            return false;
         }
       }

       std::size_t delta = count - pos;

       if(delta < length)
       {
          std::unique_ptr<char[]> Data(new char[length]);
          std::memcpy(Data.get(), headerData.get() + pos, delta);

          while(delta < length)
          {
                int ret = socket->Read(Data.get() + delta, length - delta);

                if(ret <= 0)
                {
                   err = errorReadingData_msg;
                   return false;
                }

                delta += ret;
          }

          response._data = std::span(Data.get(), length);
          responseCallback(request, response);
       }
       else
       {
          response._data = std::span(headerData.get() + pos, delta);
          responseCallback(request, response);
       }
    }
    else if(response._headers.contains(S_transferEncoding_S))
    {
       std::string_view chunked = response._headers[S_transferEncoding_S];

       if(chunked.find("chunked") == std::string_view::npos)
       {
          err = errorReadingHeader_msg;
          return false;
       }

       std::vector<char> Data;
       std::size_t readyDelta = 0;

       while(pos < count)
       {
             std::size_t chunkedSize;

             if(!getChuckSize(pos, view, chunkedSize, err)) return false;
             if(chunkedSize == 0) break;

             if(count < pos + chunkedSize)
             {
                readyDelta = ((pos + chunkedSize) - count);
                sub = view.substr(pos, (pos + chunkedSize) - (readyDelta + pos));
                Data.insert(Data.end(), sub.begin(), sub.end());
                readyDelta += 2 + chunkHeaderSize;

                break;
             }

             sub = view.substr(pos, chunkedSize);
             Data.insert(Data.end(), sub.begin(), sub.end());
             pos += chunkedSize + 2;
       }

       while(readyDelta > 0)
       {
             std::unique_ptr<char[]> socketData(new char[readyDelta]);
             std::size_t size = readyDelta - (2 + chunkHeaderSize);

             count = 0;
             for(int ret; count < size; count += ret)
             {
                 ret = socket->Read(socketData.get() + count, readyDelta - count);

                 if(ret <= 0)
                 {
                    err = incorrectChunkedSize_msg;
                    return false;
                 }
             }

             std::span part(socketData.get(), size);
             Data.insert(Data.end(), part.begin(), part.end());

             begin = 0;
             std::string_view view(socketData.get() + size + 2, readyDelta - size - 2);

             if(!getChuckSize(begin, view, readyDelta, err)) return false;
             if(readyDelta == 0) break;

             sub = view.substr(begin, view.size() - begin);
             Data.insert(Data.end(), sub.begin(), sub.end());
             readyDelta += (2 + chunkHeaderSize) - sub.size();
       }

       response._data = std::span(Data.data(), Data.size());
       responseCallback(request, response);
    }
    else
    {
       err = errorReadingHeader_msg;
       return false;
    }

    return true;
}

bool HttpClient::Get(std::string_view url, const std::function<void (const HttpRequest &, const HttpResponse &)> &responseCallback){ return sendUrl(HttpRequest::GET_METHOD, url, responseCallback); }

HttpRequest HttpClient::Get(std::string_view url)
{
    HttpRequest request;
    makeRequest(request, HttpRequest::GET_METHOD, url, nullptr);
    return request;
}

bool HttpClient::Post(std::string_view url, const HttpData &data, const std::function<void (const HttpRequest &, const HttpResponse &)> &responseCallback){ return sendUrl(HttpRequest::POST_METHOD, url, responseCallback, data); }

HttpRequest HttpClient::Post(std::string_view url, const HttpData &data)
{
    HttpRequest request;
    makeRequest(request, HttpRequest::POST_METHOD, url, nullptr, data);
    return request;
}

bool HttpClient::Put(std::string_view url, const HttpData &data, const std::function<void (const HttpRequest &, const HttpResponse &)> &responseCallback){ return sendUrl(HttpRequest::PUT_METHOD, url, responseCallback, data); }

HttpRequest HttpClient::Put(std::string_view url, const HttpData &data)
{
    HttpRequest request;
    makeRequest(request, HttpRequest::PUT_METHOD, url, nullptr, data);
    return request;
}

bool HttpClient::Patch(std::string_view url, const HttpData &data, const std::function<void (const HttpRequest &, const HttpResponse &)> &responseCallback){ return sendUrl(HttpRequest::PATCH_METHOD, url, responseCallback, data); }

HttpRequest HttpClient::Patch(std::string_view url, const HttpData &data)
{
    HttpRequest request;
    makeRequest(request, HttpRequest::PATCH_METHOD, url, nullptr, data);
    return request;
}

bool HttpClient::Delete(std::string_view url, const std::function<void (const HttpRequest &, const HttpResponse &)> &responseCallback){ return sendUrl(HttpRequest::DELETE_METHOD, url, responseCallback); }

HttpRequest HttpClient::Delete(std::string_view url)
{
    HttpRequest request;
    makeRequest(request, HttpRequest::DELETE_METHOD, url, nullptr);
    return request;
}

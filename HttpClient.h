#ifndef HTTPCLIENT_H
#define HTTPCLIENT_H

#include <functional>
#include <string>
#include <vector>
#include <map>
#include <span>
#include <memory>

//1. Need to encode URL requests and anchor from parse
//2. Need to Content-Type: Multipart/form-data
//3. Need to add fragment data callback for send and receive. Transfer-Encoding: Chunke full support API
//4. Need Compressor support: deflate, gzip, brotli
//5. Need Keep-Alive
//6. ?Ranges buffer[[buf addr1][buf addr2]...[buf addrN]] - chunk alloc?

class HttpData
{
    std::shared_ptr<char[]> _data;
    std::size_t _size = 0;

public:

    enum Type : unsigned int
    {
         Data,
         Form,
         Text,
         Json,
         Xml,
         Other
    };

    explicit HttpData();
    explicit HttpData(const char * data, std::size_t size);
    explicit HttpData(const std::vector<char> & vector);
    explicit HttpData(const std::string & string);
    explicit HttpData(std::string_view string_view);
    explicit HttpData(std::span<char> span);

    std::size_t size() const;
    std::span<char> data() const;
    virtual std::string_view contentType() const;
    virtual Type type() const;
};

class FormData : public HttpData
{
    FormData() = delete;
    static std::string makeData(const std::map<std::string, std::string> & keyValue);
public:
    explicit FormData(const std::string & string);
    explicit FormData(std::string_view string_view);
    explicit FormData(const std::map<std::string, std::string> & keyValue);

    std::string_view contentType() const override;
    Type type() const override;
};

class TextData : public HttpData
{
    TextData() = delete;
public:
    explicit TextData(std::string & string);
    explicit TextData(std::string_view string_view);

    std::string_view contentType() const override;
    Type type() const override;
};

class JsonData : public HttpData
{
    JsonData() = delete;
public:
    explicit JsonData(std::string & string);
    explicit JsonData(std::string_view string_view);

    std::string_view contentType() const override;
    Type type() const override;
};

class XmlData : public HttpData
{
    XmlData() = delete;
public:
    explicit XmlData(std::string & string);
    explicit XmlData(std::string_view string_view);

    std::string_view contentType() const override;
    Type type() const override;
};

class OtherData : public HttpData
{
    std::string _type;

    OtherData() = delete;
public:
    explicit OtherData(const std::string & type, const char * data, std::size_t size);
    explicit OtherData(const std::string & type, std::vector<char> & vector);
    explicit OtherData(const std::string & type, std::string & string);
    explicit OtherData(const std::string & type, std::string_view string_view);
    explicit OtherData(const std::string & type, std::span<char> span);

    std::string_view contentType() const override;
    Type type() const override;
};

class HttpRequest final
{
public:
    enum Protocol : unsigned char
    {
         HTTP,
         HTTPS
    };

    enum HttpMethod : unsigned char
    {
         GET_METHOD = 0,
         POST_METHOD,
         PUT_METHOD,
         PATCH_METHOD,
         DELETE_METHOD
    };

private:
    Protocol _protocol = HTTPS;
    HttpMethod _method = GET_METHOD;
    unsigned short _port = 443;
    std::shared_ptr<HttpData> _data;
    std::string _host, _path = "/", _fragment, _dataLength;
    mutable std::map<std::string,std::string> _queryes, _headers;

public:
    explicit HttpRequest();
    explicit HttpRequest(Protocol protocol, HttpMethod method, const std::string & host, unsigned short port, const std::string & path);

    void setProtocol(Protocol protocol);
    Protocol protocol() const;

    void setMethod(HttpMethod method);
    HttpMethod method() const;

    void setHost(const std::string & host);
    const std::string & host() const;

    void setPort(unsigned short port);
    unsigned short port() const;

    void setPath(const std::string & path);
    const std::string & path() const;

    int queryesCount() const;
    std::string query(const std::string & key) const;
    const std::map<std::string,std::string> & queryes() const;
    void addQuery(const std::string & key, const std::string & value);
    void addQueryes(const std::map<std::string,std::string> & values);
    void setQueryes(const std::map<std::string,std::string> & values);
    void clearQueryes();

    void setFragment(const std::string & fragment);
    const std::string & fragment() const;

    int headersCount() const;
    std::string header(const std::string & key) const;
    const std::map<std::string,std::string> & headers() const;
    void addHeader(const std::string & key, const std::string & value);
    void addHeaders(const std::map<std::string,std::string> & values);
    void setHeaders(const std::map<std::string,std::string> & values);
    void clearHeaders();

    void setData(const HttpData & data);
    HttpData * data() const;

    bool isValid() const;
    long long calculateSize() const;
    std::vector<char> make() const;
};

class HttpResponse
{
    friend class HttpClient;

    int _code;
    mutable std::map<std::string_view, std::string_view> _headers;
    std::span<char> _data;

    explicit HttpResponse();

public:
    int code() const;
    int headersCount() const;
    const std::map<std::string_view, std::string_view> & headers() const;
    std::string_view header(std::string_view key) const;
    std::span<char> data() const;
};

class HttpClient final
{
    unsigned int _maxHeaderSize;
    std::string err;
    static bool makeRequest(HttpRequest & request, HttpRequest::HttpMethod method, std::string_view url, HttpClient * client, const HttpData & data = HttpData());
    bool sendUrl(HttpRequest::HttpMethod method, std::string_view url, const std::function<void (const HttpRequest &, const HttpResponse &)> & responseCallback, const HttpData & data = HttpData());
public:
    explicit HttpClient(int maxHeaderSize = 16384);

    const std::string & error() const;
    bool sendRequest(const HttpRequest & request, const std::function<void(const HttpRequest &, const HttpResponse &)> & responseCallback);

    bool Get(std::string_view url, const std::function<void(const HttpRequest &, const HttpResponse &)> & responseCallback);
    static HttpRequest Get(std::string_view url);

    bool Post(std::string_view url, const HttpData & data, const std::function<void(const HttpRequest &, const HttpResponse &)> & responseCallback);
    static HttpRequest Post(std::string_view url, const HttpData & data);

    bool Put(std::string_view url, const HttpData & data, const std::function<void(const HttpRequest &, const HttpResponse &)> & responseCallback);
    static HttpRequest Put(std::string_view url, const HttpData & data);

    bool Patch(std::string_view url, const HttpData & data, const std::function<void(const HttpRequest &, const HttpResponse &)> & responseCallback);
    static HttpRequest Patch(std::string_view url, const HttpData & data);

    bool Delete(std::string_view url, const std::function<void(const HttpRequest &, const HttpResponse &)> & responseCallback);
    static HttpRequest Delete(std::string_view url);
};

#endif // HTTPCLIENT_H

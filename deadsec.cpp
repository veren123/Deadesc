#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <chrono>
#include <ctime>
#include <cstring>
#include <cstdlib>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <regex>
#include <mutex>
#include <algorithm>
#include <queue>
#include <atomic>
#include <functional>
#include <set>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #pragma comment(lib, "ws2_32.lib")
    #define CLEAR "cls"
    #define PATH_SEP "\\"
    #define SLEEP(ms) Sleep(ms)
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <sys/types.h>
    #include <fcntl.h>
    #include <errno.h>
    #include <ifaddrs.h>
    #include <net/if.h>
    #define CLEAR "clear"
    #define PATH_SEP "/"
    #define SLEEP(ms) usleep((ms)*1000)
    #define SOCKET int
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #define closesocket close
#endif

using namespace std;
using namespace chrono;


#ifdef _WIN32
    // Windows with ANSI support
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    #define RESET ""
    #define RED ""
    #define GREEN ""
    #define YELLOW ""
    #define BLUE ""
    #define MAGENTA ""
    #define CYAN ""
    #define WHITE ""
    #define BOLD ""
    #define DIM ""
    
    void setColor(int color) {
        SetConsoleTextAttribute(hConsole, color);
    }
#else
    #define RESET "\033[0m"
    #define RED "\033[31m"
    #define GREEN "\033[32m"
    #define YELLOW "\033[33m"
    #define BLUE "\033[34m"
    #define MAGENTA "\033[35m"
    #define CYAN "\033[36m"
    #define WHITE "\033[37m"
    #define BOLD "\033[1m"
    #define DIM "\033[2m"
#endif

// Mutex for thread safety
mutex cout_mutex;
atomic<int> ports_scanned(0);
atomic<int> ports_found(0);
atomic<int> dirs_scanned(0);
atomic<int> dirs_found(0);


void printBanner() {
    system(CLEAR);
    
    #ifdef _WIN32
        setColor(12); // Red
    #endif
    
    cout << R"(
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                                                                   ║
    ║   ██████╗ ███████╗ █████╗ ██████╗ ███████╗███████╗ ██████╗       ║
    ║   ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝       ║
    ║   ██║  ██║█████╗  ███████║██║  ██║█████╗  ███████╗██║            ║
    ║   ██║  ██║██╔══╝  ██╔══██║██║  ██║██╔══╝  ╚════██║██║            ║
    ║   ██████╔╝███████╗██║  ██║██████╔╝███████╗███████║╚██████╗       ║
    ║   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝ ╚═════╝       ║
    ║                                                                   ║
    ║                         ╔══════════════╗                         ║
    ║                         ║   by VEREN   ║                         ║
    ║                         ╚══════════════╝                         ║
    ║                                                                   ║
    ║              Advanced Reconnaissance & Security Tool             ║
    ║                  Cross-Platform | Real Data | Fast               ║
    ║                                                                   ║
    ║  [!] PERINGATAN: Jangan menyalahgunakan tools ini.               ║
    ║  [!] Segala bentuk penyalahgunaan adalah tanggung jawab penuh    ║
    ║  [!] pengguna. Pembuat tidak bertanggung jawab atas kerugian     ║
    ║  [!] atau dampak hukum yang ditimbulkan.                         ║
    ║                                                                   ║
    ╚═══════════════════════════════════════════════════════════════════╝
 )";
    
    #ifdef _WIN32
        setColor(7); // Back to white
    #endif
    
    cout << RESET << "\n\n";
}

// ====================== UTILITY FUNCTIONS ======================
string getTimestamp() {
    time_t now = time(0);
    char dt[64];
    strftime(dt, sizeof(dt), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return string(dt);
}

void showProgress(const string& message, int current, int total) {
    lock_guard<mutex> lock(cout_mutex);
    int percent = (current * 100) / total;
    int barWidth = 40;
    
    cout << "\r" << CYAN << "[*] " << message << ": [";
    int pos = barWidth * percent / 100;
    for (int i = 0; i < barWidth; ++i) {
        if (i < pos) cout << GREEN << "=";
        else if (i == pos) cout << YELLOW << ">";
        else cout << DIM << "-";
    }
    cout << CYAN << "] " << percent << "% (" << current << "/" << total << ")" << RESET;
    cout.flush();
}

// ====================== MODUL 1: DNS LOOKUP (REAL) ======================
vector<string> dnsLookup(const string& hostname) {
    vector<string> results;
    
    lock_guard<mutex> lock(cout_mutex);
    cout << YELLOW << "\n[ MODUL 1 - DNS ENUMERATION ]" << RESET << "\n";
    cout << BLUE << string(60, '-') << RESET << "\n";
    cout << "  Target : " << hostname << "\n";
    cout << BLUE << string(60, '-') << RESET << "\n\n";
    
    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    cout << "  [*] Resolving DNS records...\n";
    
    int status = getaddrinfo(hostname.c_str(), NULL, &hints, &res);
    if (status != 0) {
        cout << RED << "  [!] Error: " << gai_strerror(status) << RESET << "\n";
        return results;
    }
    
    set<string> unique_ips;
    char ipstr[INET6_ADDRSTRLEN];
    
    for (p = res; p != NULL; p = p->ai_next) {
        void* addr;
        string type;
        
        if (p->ai_family == AF_INET) {
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
            addr = &(ipv4->sin_addr);
            type = "IPv4";
        } else {
            struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            type = "IPv6";
        }
        
        inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
        unique_ips.insert(string(ipstr) + " (" + type + ")");
    }
    
    freeaddrinfo(res);
    
    cout << GREEN << "  [+] Addresses ditemukan:\n" << RESET;
    int i = 1;
    for (const auto& ip : unique_ips) {
        cout << "      " << i++ << ". " << ip << "\n";
        
        // Reverse DNS lookup
        string ip_only = ip.substr(0, ip.find(" "));
        struct sockaddr_in sa;
        sa.sin_family = AF_INET;
        if (inet_pton(AF_INET, ip_only.c_str(), &sa.sin_addr)) {
            char host[NI_MAXHOST];
            if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host), NULL, 0, 0) == 0) {
                cout << DIM << "         → PTR: " << host << RESET << "\n";
            }
        }
    }
    
    return vector<string>(unique_ips.begin(), unique_ips.end());
}

// ====================== MODUL 2: WHOIS LOOKUP (REAL) ======================
string whoisLookup(const string& domain) {
    lock_guard<mutex> lock(cout_mutex);
    cout << YELLOW << "\n[ MODUL 2 - WHOIS INTELLIGENCE ]" << RESET << "\n";
    cout << BLUE << string(60, '-') << RESET << "\n";
    cout << "  Target : " << domain << "\n";
    cout << BLUE << string(60, '-') << RESET << "\n\n";
    
    cout << "  [*] Connecting to WHOIS server...\n";
    
    // First query to IANA to get the right WHOIS server
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        cout << RED << "  [!] Error creating socket\n" << RESET;
        return "";
    }
    
    struct hostent* server = gethostbyname("whois.iana.org");
    if (!server) {
        cout << RED << "  [!] Cannot find WHOIS server\n" << RESET;
        closesocket(sock);
        return "";
    }
    
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    serv_addr.sin_port = htons(43);
    
    // Set timeout
    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);
    
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        cout << RED << "  [!] Connection to WHOIS server failed\n" << RESET;
        closesocket(sock);
        return "";
    }
    
    string query = domain + "\r\n";
    send(sock, query.c_str(), query.length(), 0);
    
    string response;
    char buffer[4096];
    int bytes;
    while ((bytes = recv(sock, buffer, sizeof(buffer)-1, 0)) > 0) {
        buffer[bytes] = '\0';
        response += buffer;
    }
    
    closesocket(sock);
    
    // Parse for the specific WHOIS server
    string whois_server = "whois.verisign-grs.com"; // Default for .com
    regex whois_regex("whois:\\s*([^\\s]+)");
    smatch match;
    
    if (regex_search(response, match, whois_regex)) {
        whois_server = match[1];
    }
    
    cout << "  [*] Querying " << whois_server << "...\n";
    
    // Query the specific WHOIS server
    sock = socket(AF_INET, SOCK_STREAM, 0);
    server = gethostbyname(whois_server.c_str());
    if (!server) {
        cout << RED << "  [!] Cannot find specific WHOIS server\n" << RESET;
        return "";
    }
    
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    serv_addr.sin_port = htons(43);
    
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        cout << RED << "  [!] Connection to specific WHOIS failed\n" << RESET;
        closesocket(sock);
        return "";
    }
    
    send(sock, query.c_str(), query.length(), 0);
    
    string final_response;
    while ((bytes = recv(sock, buffer, sizeof(buffer)-1, 0)) > 0) {
        buffer[bytes] = '\0';
        final_response += buffer;
    }
    
    closesocket(sock);
    
    // Parse and display important info
    cout << GREEN << "  [+] Informasi Domain:\n" << RESET;
    
    regex registrar_regex("Registrar:\\s*(.+?)[\\r\\n]");
    regex created_regex("Creation Date:\\s*(.+?)[\\r\\n]");
    regex expiry_regex("Expiry Date:\\s*(.+?)[\\r\\n]|Registry Expiry Date:\\s*(.+?)[\\r\\n]");
    regex name_server_regex("Name Server:\\s*(.+?)[\\r\\n]");
    regex org_regex("Registrant Organization:\\s*(.+?)[\\r\\n]");
    regex country_regex("Registrant Country:\\s*(.+?)[\\r\\n]");
    
    if (regex_search(final_response, match, org_regex)) {
        cout << "      📌 Organization : " << match[1] << "\n";
    }
    if (regex_search(final_response, match, registrar_regex)) {
        cout << "      📌 Registrar    : " << match[1] << "\n";
    }
    if (regex_search(final_response, match, created_regex)) {
        cout << "      📅 Created      : " << match[1] << "\n";
    }
    if (regex_search(final_response, match, expiry_regex)) {
        cout << "      ⏰ Expires      : " << (match[1].matched ? match[1].str() : match[2].str()) << "\n";
    }
    if (regex_search(final_response, match, country_regex)) {
        cout << "      🌍 Country      : " << match[1] << "\n";
    }
    
    cout << "      🌐 Name Servers:\n";
    sregex_iterator iter(final_response.begin(), final_response.end(), name_server_regex);
    sregex_iterator end;
    int ns_count = 0;
    for (; iter != end; ++iter) {
        cout << "         - " << (*iter)[1] << "\n";
        ns_count++;
    }
    if (ns_count == 0) {
        cout << "         (Tidak ditemukan)\n";
    }
    
    return final_response;
}

// ====================== MODUL 3: HTTP HEADER & TECHNOLOGY (REAL) ======================
string httpRequest(const string& host, int port = 80) {
    cout << "  [*] Connecting to " << host << ":" << port << "...\n";
    
    struct hostent* server = gethostbyname(host.c_str());
    if (!server) {
        cout << RED << "  [!] Host not found\n" << RESET;
        return "";
    }
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        cout << RED << "  [!] Socket error\n" << RESET;
        return "";
    }
    
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    serv_addr.sin_port = htons(port);
    
    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);
    
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        cout << RED << "  [!] Connection refused\n" << RESET;
        closesocket(sock);
        return "";
    }
    
    string request = "HEAD / HTTP/1.1\r\n"
                     "Host: " + host + "\r\n"
                     "User-Agent: DEADSEC-VRN/2.0\r\n"
                     "Accept: */*\r\n"
                     "Connection: close\r\n\r\n";
    
    send(sock, request.c_str(), request.length(), 0);
    
    string response;
    char buffer[4096];
    int bytes;
    
    while ((bytes = recv(sock, buffer, sizeof(buffer)-1, 0)) > 0) {
        buffer[bytes] = '\0';
        response += buffer;
        if (response.find("\r\n\r\n") != string::npos) break;
    }
    
    closesocket(sock);
    
    return response;
}

void analyzeTechnology(const string& headers) {
    cout << GREEN << "  [+] Teknologi Terdeteksi:\n" << RESET;
    
    // Web Server
    regex server_regex("Server:\\s*(.+?)[\\r\\n]", regex::icase);
    smatch match;
    if (regex_search(headers, match, server_regex)) {
        cout << "      🌐 Web Server  : " << match[1] << "\n";
    }
    
    // Framework/Language
    regex powered_regex("X-Powered-By:\\s*(.+?)[\\r\\n]", regex::icase);
    if (regex_search(headers, match, powered_regex)) {
        cout << "      ⚡ Powered By  : " << match[1] << "\n";
    }
    
    // ASP.NET
    regex asp_regex("X-AspNet-Version:\\s*(.+?)[\\r\\n]", regex::icase);
    if (regex_search(headers, match, asp_regex)) {
        cout << "      🔷 ASP.NET     : Version " << match[1] << "\n";
    }
    
    // CMS Detection
    if (headers.find("wp-") != string::npos || headers.find("WordPress") != string::npos) {
        cout << "      📝 CMS         : WordPress\n";
    }
    if (headers.find("Joomla") != string::npos) {
        cout << "      📝 CMS         : Joomla\n";
    }
    if (headers.find("Drupal") != string::npos) {
        cout << "      📝 CMS         : Drupal\n";
    }
    if (headers.find("X-Drupal-Cache") != string::npos) {
        cout << "      📝 CMS         : Drupal\n";
    }
    
    // Cloudflare
    if (headers.find("CF-RAY") != string::npos || headers.find("cloudflare") != string::npos) {
        cout << "      ☁️  CDN         : Cloudflare\n";
    }
}

void analyzeSecurity(const string& headers) {
    cout << GREEN << "  [+] Security Headers:\n" << RESET;
    
    map<string, string> security_headers = {
        {"Strict-Transport-Security", "HSTS - Proteksi SSL stripping"},
        {"Content-Security-Policy", "CSP - Mencegah XSS & injection"},
        {"X-Frame-Options", "Clickjacking Protection"},
        {"X-Content-Type-Options", "MIME Sniffing Protection"},
        {"X-XSS-Protection", "XSS Filter"},
        {"Referrer-Policy", "Referrer Information Control"}
    };
    
    string lower_headers = headers;
    transform(lower_headers.begin(), lower_headers.end(), lower_headers.begin(), ::tolower);
    
    for (const auto& header : security_headers) {
        string lower_header = header.first;
        transform(lower_header.begin(), lower_header.end(), lower_header.begin(), ::tolower);
        
        if (lower_headers.find(lower_header) != string::npos) {
            cout << "      ✅ " << header.first << "\n";
            cout << DIM << "         └─ " << header.second << RESET << "\n";
        } else {
            cout << "      ❌ " << header.first << " (MISSING)\n";
        }
    }
    
    // Cookie Analysis
    regex cookie_regex("Set-Cookie:\\s*([^;]+)", regex::icase);
    sregex_iterator iter(headers.begin(), headers.end(), cookie_regex);
    sregex_iterator end;
    
    if (iter != end) {
        cout << GREEN << "  [+] Cookie Security:\n" << RESET;
        for (; iter != end; ++iter) {
            string cookie = (*iter)[1];
            cout << "      🍪 " << cookie << "\n";
            
            if (headers.find("Secure") != string::npos)
                cout << "         ├─ Secure  : " << GREEN << "YES" << RESET << "\n";
            else
                cout << "         ├─ Secure  : " << RED << "NO" << RESET << "\n";
                
            if (headers.find("HttpOnly") != string::npos)
                cout << "         └─ HttpOnly: " << GREEN << "YES" << RESET << "\n";
            else
                cout << "         └─ HttpOnly: " << RED << "NO" << RESET << "\n";
        }
    }
}

// ====================== MODUL 4: PORT SCANNER (REAL) ======================
class PortScanner {
private:
    string target_ip;
    int thread_count;
    int timeout_ms;
    vector<int> open_ports;
    map<int, string> service_map;
    
    string getServiceName(int port, const string& banner) {
        // Common ports
        map<int, string> common = {
            {20, "FTP-data"}, {21, "FTP"}, {22, "SSH"}, {23, "Telnet"},
            {25, "SMTP"}, {53, "DNS"}, {80, "HTTP"}, {110, "POP3"},
            {111, "RPC"}, {135, "MSRPC"}, {139, "NetBIOS"}, {143, "IMAP"},
            {443, "HTTPS"}, {445, "SMB"}, {993, "IMAPS"}, {995, "POP3S"},
            {1723, "PPTP"}, {3306, "MySQL"}, {3389, "RDP"}, {5432, "PostgreSQL"},
            {5900, "VNC"}, {6379, "Redis"}, {8080, "HTTP-Alt"}, {8443, "HTTPS-Alt"},
            {27017, "MongoDB"}, {27018, "MongoDB"}, {5000, "Docker"}, {2375, "Docker-REST"}
        };
        
        if (common.count(port)) {
            return common[port];
        }
        
        // Try to identify from banner
        string lower_banner = banner;
        transform(lower_banner.begin(), lower_banner.end(), lower_banner.begin(), ::tolower);
        
        if (lower_banner.find("ssh") != string::npos) return "SSH";
        if (lower_banner.find("ftp") != string::npos) return "FTP";
        if (lower_banner.find("http") != string::npos) return "HTTP";
        if (lower_banner.find("smtp") != string::npos) return "SMTP";
        if (lower_banner.find("mysql") != string::npos) return "MySQL";
        
        return "unknown";
    }
    
    bool scanPort(int port) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return false;
        
        #ifdef _WIN32
            u_long mode = 1;
            ioctlsocket(sock, FIONBIO, &mode);
        #else
            int flags = fcntl(sock, F_GETFL, 0);
            fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        #endif
        
        struct sockaddr_in server;
        server.sin_family = AF_INET;
        server.sin_port = htons(port);
        inet_pton(AF_INET, target_ip.c_str(), &server.sin_addr);
        
        connect(sock, (struct sockaddr*)&server, sizeof(server));
        
        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        
        bool connected = false;
        if (select(sock + 1, NULL, &fdset, NULL, &tv) == 1) {
            int so_error;
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len);
            if (so_error == 0) {
                connected = true;
                
                
                char banner[1024] = {0};
                send(sock, "HEAD / HTTP/1.0\r\n\r\n", 19, 0);
                recv(sock, banner, sizeof(banner) - 1, 0);
                service_map[port] = getServiceName(port, string(banner));
            }
        }
        
        #ifdef _WIN32
            closesocket(sock);
        #else
            close(sock);
        #endif
        
        ports_scanned++;
        return connected;
    }
    
public:
    PortScanner(const string& ip, int threads = 100, int timeout = 1000) 
        : target_ip(ip), thread_count(threads), timeout_ms(timeout) {}
    
    vector<int> scan() {
        lock_guard<mutex> lock(cout_mutex);
        cout << YELLOW << "\n[ MODUL 4 - Speed_Scanner]" << RESET << "\n";
        cout << BLUE << string(60, '-') << RESET << "\n";
        cout << "  Target IP : " << target_ip << "\n";
        cout << "  Port range: 1-65535\n";
        cout << "  Threads   : " << thread_count << "\n";
        cout << "  Timeout   : " << timeout_ms << "ms\n";
        cout << BLUE << string(60, '-') << RESET << "\n\n";
        
        auto start_time = high_resolution_clock::now();
        vector<thread> threads;
        int ports_per_thread = 65535 / thread_count;
        ports_scanned = 0;
        ports_found = 0;
        
        // Progress thread
        atomic<bool> scanning_complete(false);
        thread progress_thread([&]() {
            while (!scanning_complete) {
                int scanned = ports_scanned.load();
                showProgress("Scanning ports", scanned, 65535);
                this_thread::sleep_for(milliseconds(100));
            }
        });
        
        // Scanner threads
        for (int t = 0; t < thread_count; t++) {
            int start_port = t * ports_per_thread + 1;
            int end_port = (t == thread_count - 1) ? 65535 : (t + 1) * ports_per_thread;
            
            threads.emplace_back([this, start_port, end_port]() {
                for (int port = start_port; port <= end_port; port++) {
                    if (scanPort(port)) {
                        lock_guard<mutex> lock(cout_mutex);
                        open_ports.push_back(port);
                        ports_found++;
                    }
                }
            });
        }
        
            // Wait for all threads
        for (auto& t : threads) {
            t.join();
        }
        
        scanning_complete = true;
        progress_thread.join();
        
        auto end_time = high_resolution_clock::now();
auto duration = duration_cast<seconds>(end_time - start_time);

        
        // Sort results
        sort(open_ports.begin(), open_ports.end());
        
        cout << "\n\n";
        cout << GREEN << "  [+] Scan Complete!\n" << RESET;
        cout << "      Waktu     : " << duration.count() << " detik\n";
        cout << "      Port Open : " << ports_found << " ditemukan\n\n";
        scanning_complete = true;
        progress_thread.join();
        
        end_time = high_resolution_clock::now(); 
duration = duration_cast<seconds>(end_time - start_time);
        
        // Sort results
        sort(open_ports.begin(), open_ports.end());
        
        cout << "\n\n";
        cout << GREEN << "  [+] Scan Complete!\n" << RESET;
        cout << "      Waktu     : " << duration.count() << " detik\n";
        cout << "      Port Open : " << ports_found << " ditemukan\n\n";
        
        if (!open_ports.empty()) {
            cout << GREEN << "  📍 OPEN PORTS:\n" << RESET;
            cout << "  " << BLUE << string(50, '-') << RESET << "\n";
            cout << "    PORT     STATE    SERVICE\n";
            cout << "  " << BLUE << string(50, '-') << RESET << "\n";
            
            for (int port : open_ports) {
                printf("    %-5d   open     %s\n", port, service_map[port].c_str());
            }
            cout << "  " << BLUE << string(50, '-') << RESET << "\n";
        }
        
        return open_ports;
    }
};

// ====================== MODUL 5: HIDDEN FILE/DIRECTORY FINDER (REAL) ======================
class DirBuster {
private:
    string target_url;
    vector<string> wordlist;
    vector<string> found_items;
    int thread_count;
    int timeout_ms;
    
    vector<string> generateWordlist() {
        return {
            // Admin panels
            "admin", "administrator", "admin.php", "admin.html", "admin.asp",
            "admin.aspx", "admin.jsp", "admin/", "administrator/", "wp-admin",
            "wp-admin/", "cpanel", "webadmin", "backend", "controlpanel",
            "management", "manager", "login", "signin", "auth",
            
            // Hidden files
            ".git/", ".git/config", ".git/HEAD", ".svn/", ".svn/entries",
            ".htaccess", ".htpasswd", ".env", ".env.example", ".bash_history",
            ".ssh/", ".ssh/id_rsa", ".aws/credentials", ".npmrc", ".dockerenv",
            ".DS_Store", ".gitignore", ".htpasswd", ".htaccess.bak",
            
            // Config files
            "config.php", "config.asp", "config.jsp", "configuration.php",
            "web.config", "app.config", "settings.py", "wp-config.php",
            "database.yml", "application.properties", "config.ini",
            "config.json", "config.xml", "settings.json",
            
            // Backup files
            "backup.zip", "backup.tar.gz", "backup.sql", "db_backup.sql",
            "dump.sql", "backup/", "backups/", "bak/", "old/", "tmp/",
            "temp/", "backup.php", "index.php~", "index.php.bak", "*.swp",
            "backup.db", "database.sql", "db.sql", "backup.rar",
                 // Sensitive directories
            "logs/", "log/", "error_log", "access_log", "debug/",
            "phpinfo.php", "info.php", "test.php", "shell.php",
            "upload.php", "uploads/", "files/", "download/",
            "images/", "img/", "css/", "js/", "static/", "assets/",
            
            // API endpoints
            "api/", "api/v1/", "api/v2/", "rest/", "soap/", "graphql",
            "swagger", "swagger-ui", "docs/", "documentation/",
            "api/docs", "api/swagger", "api.json", "api.xml",
            
            // Version control & info
            "VERSION", "RELEASE", "CHANGELOG", "LICENSE", "README.md",
            "composer.json", "package.json", "requirements.txt",
            "robots.txt", "sitemap.xml", "crossdomain.xml",
            
            // Development tools
            "phpmyadmin", "phpPgAdmin", "adminer", "mysql/", "myadmin/",
            "pma/", "webmail", "mail/", "roundcube", "horde",
            "phpMyAdmin/", "phpmyadmin/", "mysqladmin/",
            
            // Common CMS paths
            "wp-content/", "wp-includes/", "wp-json/", "xmlrpc.php",
            "wp-login.php", "wp-signup.php", "wp-activate.php",
            "administrator/", "components/", "modules/", "plugins/",
            "templates/", "cache/", "tmp/", "sites/", "sites/all/",
            
            // Other interesting paths
            "cgi-bin/", "cgi-bin/test.cgi", "cgi-bin/printenv",
            "server-status", "server-info", "status", "info",
            "test/", "tests/", "testing/", "dev/", "development/",
            "staging/", "stage/", "prod/", "production/",
            
            // File uploads
            "upload/", "uploads/", "files/", "media/", "downloads/",
            "attachments/", "images/", "img/", "assets/", "resources/",
            
            // Source code
            "src/", "source/", "lib/", "vendor/", "node_modules/",
            "bower_components/", "dist/", "build/", "out/"
        };
    }
    
    bool checkPath(const string& path) {
        string full_url = target_url + path;
        
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return false;
        
        // Parse URL
        string host = target_url;
        size_t pos = host.find("://");
        if (pos != string::npos) {
            host = host.substr(pos + 3);
        }
        pos = host.find("/");
        if (pos != string::npos) {
            host = host.substr(0, pos);
        }
        
        struct hostent* server = gethostbyname(host.c_str());
        if (!server) {
            closesocket(sock);
            return false;
        }
        
        struct sockaddr_in serv_addr;
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
        serv_addr.sin_port = htons(80);
        
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);
        
        if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
            closesocket(sock);
            return false;
        }
        
        string request = "GET " + path + " HTTP/1.1\r\n"
                         "Host: " + host + "\r\n"
                         "User-Agent: DEADSEC-DirBuster/2.0\r\n"
                         "Accept: */*\r\n"
                         "Connection: close\r\n\r\n";
        
        send(sock, request.c_str(), request.length(), 0);
        
        char response[4096];
        int bytes = recv(sock, response, sizeof(response)-1, 0);
        closesocket(sock);
        
        if (bytes > 0) {
            response[bytes] = '\0';
            string resp_str(response);
            
            // Check if found (200 OK, 403 Forbidden, 301 Moved, 401 Unauthorized)
            if (resp_str.find("200 OK") != string::npos ||
                resp_str.find("403 Forbidden") != string::npos ||
                resp_str.find("301 Moved") != string::npos ||
                resp_str.find("302 Found") != string::npos ||
                resp_str.find("401 Unauthorized") != string::npos) {
                return true;
            }
        }
        
        return false;
    }
    
public:
    DirBuster(const string& url, int threads = 30, int timeout = 3000) 
        : target_url(url), thread_count(threads), timeout_ms(timeout) {
        wordlist = generateWordlist();
    }
    
    vector<string> scan() {
        lock_guard<mutex> lock(cout_mutex);
        cout << YELLOW << "\n[ MODUL 5 - HIDDEN FILE/DIRECTORY FINDER ]" << RESET << "\n";
        cout << BLUE << string(60, '-') << RESET << "\n";
        cout << "  Target URL : " << target_url << "\n";
        cout << "  Wordlist   : " << wordlist.size() << " entries\n";
        cout << "  Threads    : " << thread_count << "\n";
        cout << BLUE << string(60, '-') << RESET << "\n\n";
        
        auto start_time = high_resolution_clock::now();
        
        atomic<int> checked(0);
        atomic<bool> scanning_complete(false);
        vector<thread> threads;
        found_items.clear();
        dirs_scanned = 0;
        dirs_found = 0;
        
        // Progress thread
        thread progress_thread([&]() {
            int total = wordlist.size();
            while (!scanning_complete) {
                int done = checked.load();
                showProgress("Scanning paths", done, total);
                this_thread::sleep_for(milliseconds(100));
            }
        });
        
        // Worker threads
        int items_per_thread = wordlist.size() / thread_count;
        for (int t = 0; t < thread_count; t++) {
            int start = t * items_per_thread;
            int end = (t == thread_count - 1) ? wordlist.size() : (t + 1) * items_per_thread;
            
            threads.emplace_back([this, start, end, &checked]() {
                for (int i = start; i < end; i++) {
                    if (checkPath(wordlist[i])) {
                        lock_guard<mutex> lock(cout_mutex);
                        found_items.push_back(wordlist[i]);
                        dirs_found++;
                        cout << "\n  " << GREEN << "[+] FOUND: " << RESET 
                             << target_url << "/" << wordlist[i] << "\n";
                        cout.flush();
                    }
                    checked++;
                    dirs_scanned++;
                }
            });
        }
        
        // Wait for threads
        for (auto& t : threads) {
            t.join();
        }
        
        scanning_complete = true;
        progress_thread.join();
        
        auto end_time = high_resolution_clock::now();
        auto duration = duration_cast<seconds>(end_time - start_time);
        
        cout << "\n\n";
        cout << GREEN << "  [+] Directory Scan Complete!\n" << RESET;
        cout << "      Waktu    : " << duration.count() << " detik\n";
        cout << "      Ditemukan: " << found_items.size() << " item\n\n";
        
        if (!found_items.empty()) {
            cout << GREEN << "  📍 HIDDEN ITEMS FOUND:\n" << RESET;
            cout << "  " << BLUE << string(50, '-') << RESET << "\n";
            set<string> unique_items(found_items.begin(), found_items.end());
            for (const auto& item : unique_items) {
                cout << "    " << YELLOW << "➤ " << RESET << target_url << "/" << item << "\n";
            }
            cout << "  " << BLUE << string(50, '-') << RESET << "\n";
        }
        
        return found_items;
    }
};

// ====================== MAIN FUNCTION ======================
int main() {
    // Initialize sockets for Windows
    #ifdef _WIN32
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
        system("color 0A");
    #endif
    
    printBanner();
    
    string target;
    cout << BOLD << "╭─ Target [" << GREEN << "?" << RESET << BOLD << "]: " << RESET;
    getline(cin, target);
    
    if (target.empty()) {
        target = "example.com";
        cout << YELLOW << "  [!] Target kosong, menggunakan default: " << target << RESET << "\n";
    }
    
    // Remove http:// or https:// if present
    string clean_target = target;
    size_t pos = clean_target.find("://");
    if (pos != string::npos) {
        clean_target = clean_target.substr(pos + 3);
    }
    pos = clean_target.find("/");
    if (pos != string::npos) {
        clean_target = clean_target.substr(0, pos);
    }
    
    cout << BOLD << "\n╰─ Scanning: " << CYAN << clean_target << RESET << "\n\n";
    cout << BLUE << string(60, '=') << RESET << "\n";
    
    // MODUL 1: DNS LOOKUP
    vector<string> ips = dnsLookup(clean_target);
    
    cout << "\n" << BLUE << string(60, '=') << RESET << "\n";
    
    // MODUL 2: WHOIS
    string whois_result = whoisLookup(clean_target);
    
    cout << "\n" << BLUE << string(60, '=') << RESET << "\n";
    
    // MODUL 3: HTTP HEADER & TECHNOLOGY
    cout << YELLOW << "\n[ MODUL 3 - WEB TECHNOLOGY & SECURITY ]" << RESET << "\n";
    cout << BLUE << string(60, '-') << RESET << "\n";
    cout << "  Target : " << clean_target << "\n";
    cout << BLUE << string(60, '-') << RESET << "\n\n";
    
    string headers = httpRequest(clean_target, 80);
    if (!headers.empty()) {
        analyzeTechnology(headers);
        cout << "\n";
        analyzeSecurity(headers);
        
        cout << DIM << "\n  [Raw Headers]\n";
        cout << headers.substr(0, 500) << RESET << "\n";
    } else {
        // Try HTTPS if HTTP fails
        cout << YELLOW << "  [!] HTTP failed, trying HTTPS...\n" << RESET;
        headers = httpRequest(clean_target, 443);
        if (!headers.empty()) {
            analyzeTechnology(headers);
            cout << "\n";
            analyzeSecurity(headers);
        } else {
            cout << RED << "  [!] Gagal mendapatkan response HTTP/HTTPS\n" << RESET;
        }
    }
    
    cout << "\n" << BLUE << string(60, '=') << RESET << "\n";
    
    // MODUL 4: PORT SCANNER
    if (!ips.empty()) {
        string ip = ips[0].substr(0, ips[0].find(" "));
        PortScanner scanner(ip, 100, 1000);
        vector<int> open_ports = scanner.scan();
    }
    
    cout << "\n" << BLUE << string(60, '=') << RESET << "\n";
    
    // MODUL 5: HIDDEN FILE FINDER
    string url = "http://" + clean_target;
    DirBuster dirbuster(url, 30, 3000);
    vector<string> hidden_items = dirbuster.scan();
    
    cout << "\n" << BLUE << string(60, '=') << RESET << "\n\n";
    
    // FINAL REPORT
    cout << GREEN << BOLD << "✓ SCAN COMPLETED" << RESET << "\n";
    cout << "  Target     : " << clean_target << "\n";
    cout << "  Waktu      : " << getTimestamp() << "\n";
    cout << "  Scanner    : DEADSEC by VEREN\n\n";
    
    // Save report
    time_t now = time(0);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", localtime(&now));
    
    string filename = "deadsec_" + clean_target + "_" + timestamp + ".txt";
    // Replace invalid characters
    replace(filename.begin(), filename.end(), '/', '_');
    replace(filename.begin(), filename.end(), ':', '_');
    
    ofstream report(filename);
    if (report.is_open()) {
        report << "DEADSEC - Advanced Reconnaissance Tool\n";
        report << "========================================\n";
        report << "Target    : " << clean_target << "\n";
        report << "Timestamp : " << getTimestamp() << "\n";
        report << "Scanner   : VEREN\n\n";
        
        report << "=== SCAN SUMMARY ===\n";
        report << "DNS Records  : " << ips.size() << "\n";
        report << "Open Ports   : " << ports_found << "\n";
        report << "Hidden Items : " << hidden_items.size() << "\n";
        report.close();
        
        cout << CYAN << "📁 Report saved: " << filename << RESET << "\n\n";
    }
    
    cout << DIM << "Press Enter to exit..." << RESET;
    cin.ignore();
    cin.get();
    
    #ifdef _WIN32
        WSACleanup();
    #endif
    
    return 0;
}
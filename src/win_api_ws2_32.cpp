/**
 * VXEngine ws2_32.dll API Stubs
 *
 * Emulated Winsock functions for network behavior analysis.
 * All connections are fake — no real network traffic occurs.
 * IOCs (IPs, hostnames, ports) are logged for behavioral analysis.
 */

#include "vxengine/engine.h"
#include "vxengine/memory.h"
#include "vxengine/cpu/icpu.h"
#include <map>
#include <vector>
#include <string>
#include <cstring>
#include <cstdio>
#include <sstream>
#include <iomanip>

namespace vx {

// ============================================================
// Internal state
// ============================================================

struct SocketInfo {
    uint32_t handle;
    int af;      // AF_INET=2
    int type;    // SOCK_STREAM=1, SOCK_DGRAM=2
    int proto;
    std::string remote_ip;
    uint16_t remote_port = 0;
    bool connected = false;
};

struct NetworkIOC {
    std::string type;   // "socket", "connect", "dns", "send", "recv"
    std::string ip;
    uint16_t port = 0;
    std::string hostname;
    std::vector<uint8_t> data_preview;  // First 64 bytes of sent data
};

static std::map<uint32_t, SocketInfo> s_sockets;
static std::vector<NetworkIOC> s_network_iocs;
static uint32_t s_next_socket = 0x1000;
static int s_wsa_error = 0;
static bool s_wsa_initialized = false;

// ============================================================
// Helpers
// ============================================================

static std::string read_guest_string(VirtualMemory& vmem, uint64_t addr, size_t max_len = 1024) {
    std::string result;
    for (size_t i = 0; i < max_len; ++i) {
        uint8_t ch = 0;
        vmem.read(addr + i, &ch, 1);
        if (ch == 0) break;
        result += static_cast<char>(ch);
    }
    return result;
}

static std::string ip_to_string(uint32_t ip_be) {
    // ip_be is in network byte order (big-endian)
    return std::to_string(ip_be & 0xFF) + "." +
           std::to_string((ip_be >> 8) & 0xFF) + "." +
           std::to_string((ip_be >> 16) & 0xFF) + "." +
           std::to_string((ip_be >> 24) & 0xFF);
}

static uint16_t swap16(uint16_t v) {
    return (v >> 8) | (v << 8);
}

static uint32_t swap32(uint32_t v) {
    return ((v >> 24) & 0xFF) | ((v >> 8) & 0xFF00) |
           ((v << 8) & 0xFF0000) | ((v << 24) & 0xFF000000);
}

// Fake addrinfo/hostent allocation in guest memory
static uint32_t s_net_scratch_base = 0x09000000;
static uint32_t s_net_scratch_ptr = 0x09000000;
static bool s_net_scratch_mapped = false;

static uint32_t alloc_scratch(VirtualMemory& vmem, uint32_t size) {
    if (!s_net_scratch_mapped) {
        vmem.map(s_net_scratch_base, 0x00100000, 0x06); // RW, 1MB
        s_net_scratch_mapped = true;
    }
    uint32_t addr = s_net_scratch_ptr;
    s_net_scratch_ptr += (size + 15) & ~15; // 16-byte align
    return addr;
}

// ============================================================
// Registration
// ============================================================

void register_ws2_32_apis(APIDispatcher& api) {

    // --- WSAStartup(wVersionRequired, lpWSAData) ---
    // 2 args, stdcall
    api.register_api("WSAStartup", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        uint32_t version = vmem.read32(cpu.sp() + 4);
        uint32_t lpWSAData = vmem.read32(cpu.sp() + 8);
        cpu.set_sp(cpu.sp() + 8); // pop 2 args

        // Write WSADATA structure (at least first 16 bytes)
        if (lpWSAData) {
            vmem.write32(lpWSAData + 0, version);     // wVersion
            vmem.write32(lpWSAData + 2, version);     // wHighVersion (same)
            // Zero the rest (description, system status, etc.)
            for (int i = 4; i < 400; i += 4) {
                vmem.write32(lpWSAData + i, 0);
            }
        }

        s_wsa_initialized = true;
        return 0; // Success
    });

    // --- WSACleanup() ---
    // 0 args
    api.register_api("WSACleanup", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        s_wsa_initialized = false;
        return 0;
    });

    // --- WSAGetLastError() ---
    // 0 args
    api.register_api("WSAGetLastError", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        return static_cast<uint64_t>(s_wsa_error);
    });

    // --- WSASetLastError(iError) ---
    // 1 arg
    api.register_api("WSASetLastError", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        s_wsa_error = static_cast<int>(vmem.read32(cpu.sp() + 4));
        cpu.set_sp(cpu.sp() + 4);
        return 0;
    });

    // --- socket(af, type, protocol) ---
    // 3 args
    api.register_api("socket", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        int af = static_cast<int>(vmem.read32(cpu.sp() + 4));
        int type = static_cast<int>(vmem.read32(cpu.sp() + 8));
        int proto = static_cast<int>(vmem.read32(cpu.sp() + 12));
        cpu.set_sp(cpu.sp() + 12);

        uint32_t handle = s_next_socket++;
        s_sockets[handle] = {handle, af, type, proto, "", 0, false};

        s_network_iocs.push_back({"socket", "", 0, ""});
        return handle;
    });

    // --- connect(s, name, namelen) ---
    // 3 args
    api.register_api("connect", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        uint32_t sock = vmem.read32(cpu.sp() + 4);
        uint32_t name_addr = vmem.read32(cpu.sp() + 8);
        uint32_t namelen = vmem.read32(cpu.sp() + 12);
        cpu.set_sp(cpu.sp() + 12);

        // Parse sockaddr_in: family(2) + port(2) + ip(4)
        uint16_t family = vmem.read32(name_addr) & 0xFFFF;
        uint16_t port_be = (vmem.read32(name_addr + 2) & 0xFFFF);
        uint16_t port = swap16(port_be);
        uint32_t ip_be = vmem.read32(name_addr + 4);
        std::string ip_str = ip_to_string(ip_be);

        auto it = s_sockets.find(sock);
        if (it != s_sockets.end()) {
            it->second.remote_ip = ip_str;
            it->second.remote_port = port;
            it->second.connected = true;
        }

        s_network_iocs.push_back({"connect", ip_str, port, ""});
        return 0; // Success
    });

    // --- bind(s, name, namelen) ---
    // 3 args
    api.register_api("bind", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        cpu.set_sp(cpu.sp() + 12);
        return 0;
    });

    // --- listen(s, backlog) ---
    // 2 args
    api.register_api("listen", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        cpu.set_sp(cpu.sp() + 8);
        return 0;
    });

    // --- accept(s, addr, addrlen) ---
    // 3 args
    api.register_api("accept", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        cpu.set_sp(cpu.sp() + 12);
        uint32_t new_sock = s_next_socket++;
        s_sockets[new_sock] = {new_sock, 2, 1, 0, "10.0.0.1", 12345, true};
        return new_sock;
    });

    // --- send(s, buf, len, flags) ---
    // 4 args
    api.register_api("send", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        uint32_t sock = vmem.read32(cpu.sp() + 4);
        uint32_t buf_addr = vmem.read32(cpu.sp() + 8);
        uint32_t len = vmem.read32(cpu.sp() + 12);
        uint32_t flags = vmem.read32(cpu.sp() + 16);
        cpu.set_sp(cpu.sp() + 16);

        // Read data preview (first 64 bytes)
        NetworkIOC ioc;
        ioc.type = "send";
        auto it = s_sockets.find(sock);
        if (it != s_sockets.end()) {
            ioc.ip = it->second.remote_ip;
            ioc.port = it->second.remote_port;
        }
        uint32_t preview_len = len < 64 ? len : 64;
        ioc.data_preview.resize(preview_len);
        vmem.read(buf_addr, ioc.data_preview.data(), preview_len);
        s_network_iocs.push_back(std::move(ioc));

        return len; // Pretend all bytes sent
    });

    // --- recv(s, buf, len, flags) ---
    // 4 args
    api.register_api("recv", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        uint32_t sock = vmem.read32(cpu.sp() + 4);
        uint32_t buf_addr = vmem.read32(cpu.sp() + 8);
        uint32_t len = vmem.read32(cpu.sp() + 12);
        uint32_t flags = vmem.read32(cpu.sp() + 16);
        cpu.set_sp(cpu.sp() + 16);

        // Write fake response (empty — return 0 bytes to simulate closed connection)
        // This causes most malware to move on to next stage
        s_network_iocs.push_back({"recv", "", 0, ""});
        return 0; // 0 bytes received = connection closed
    });

    // --- closesocket(s) ---
    // 1 arg
    api.register_api("closesocket", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        uint32_t sock = vmem.read32(cpu.sp() + 4);
        cpu.set_sp(cpu.sp() + 4);
        s_sockets.erase(sock);
        return 0;
    });

    // --- gethostbyname(name) ---
    // 1 arg
    api.register_api("gethostbyname", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        uint32_t name_addr = vmem.read32(cpu.sp() + 4);
        cpu.set_sp(cpu.sp() + 4);

        std::string hostname = read_guest_string(vmem, name_addr);
        s_network_iocs.push_back({"dns", "", 0, hostname});

        // Build fake hostent structure in scratch memory
        // struct hostent { char* h_name; char** h_aliases; short h_addrtype; short h_length; char** h_addr_list; }
        uint32_t hostent_addr = alloc_scratch(vmem, 256);

        // Write hostname
        uint32_t name_buf = hostent_addr + 64;
        vmem.write(name_buf, hostname.c_str(), hostname.size() + 1);

        // Write fake IP address (127.0.0.1 in network byte order = 0x0100007F)
        uint32_t ip_buf = hostent_addr + 192;
        uint32_t fake_ip = 0x0100007F; // 127.0.0.1 in network byte order
        vmem.write32(ip_buf, fake_ip);

        // Write addr_list (pointer to ip_buf, then NULL)
        uint32_t addr_list = hostent_addr + 200;
        vmem.write32(addr_list, ip_buf);
        vmem.write32(addr_list + 4, 0);

        // Write aliases (NULL)
        uint32_t aliases = hostent_addr + 208;
        vmem.write32(aliases, 0);

        // Fill hostent struct
        vmem.write32(hostent_addr + 0, name_buf);       // h_name
        vmem.write32(hostent_addr + 4, aliases);         // h_aliases
        // h_addrtype(2 bytes) + h_length(2 bytes) = 4 bytes total at offset 8
        uint16_t addrtype = 2; // AF_INET
        uint16_t addrlen = 4;
        vmem.write(hostent_addr + 8, &addrtype, 2);
        vmem.write(hostent_addr + 10, &addrlen, 2);
        vmem.write32(hostent_addr + 12, addr_list);      // h_addr_list

        return hostent_addr;
    });

    // --- getaddrinfo(pNodeName, pServiceName, pHints, ppResult) ---
    // 4 args
    api.register_api("getaddrinfo", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        uint32_t node_addr = vmem.read32(cpu.sp() + 4);
        uint32_t svc_addr = vmem.read32(cpu.sp() + 8);
        uint32_t hints_addr = vmem.read32(cpu.sp() + 12);
        uint32_t result_addr = vmem.read32(cpu.sp() + 16);
        cpu.set_sp(cpu.sp() + 16);

        std::string hostname = node_addr ? read_guest_string(vmem, node_addr) : "";
        if (!hostname.empty()) {
            s_network_iocs.push_back({"dns", "", 0, hostname});
        }

        // Build fake addrinfo chain
        // struct addrinfo { int flags; int family; int socktype; int protocol;
        //                   size_t addrlen; char* canonname; struct sockaddr* addr; struct addrinfo* next; }
        uint32_t ai_addr = alloc_scratch(vmem, 128);

        // sockaddr_in at ai_addr + 64
        uint32_t sa_addr = ai_addr + 64;
        uint16_t sa_family = 2; // AF_INET
        vmem.write(sa_addr, &sa_family, 2);
        uint16_t sa_port = 0;
        vmem.write(sa_addr + 2, &sa_port, 2);
        uint32_t sa_ip = 0x0100007F; // 127.0.0.1
        vmem.write32(sa_addr + 4, sa_ip);

        // addrinfo struct
        vmem.write32(ai_addr + 0, 0);          // ai_flags
        vmem.write32(ai_addr + 4, 2);          // ai_family = AF_INET
        vmem.write32(ai_addr + 8, 1);          // ai_socktype = SOCK_STREAM
        vmem.write32(ai_addr + 12, 6);         // ai_protocol = IPPROTO_TCP
        vmem.write32(ai_addr + 16, 16);        // ai_addrlen = sizeof(sockaddr_in)
        vmem.write32(ai_addr + 20, 0);         // ai_canonname = NULL
        vmem.write32(ai_addr + 24, sa_addr);   // ai_addr
        vmem.write32(ai_addr + 28, 0);         // ai_next = NULL

        // Write pointer to addrinfo into ppResult
        if (result_addr) {
            vmem.write32(result_addr, ai_addr);
        }

        return 0; // Success
    });

    // --- freeaddrinfo(pAddrInfo) ---
    // 1 arg, void return
    api.register_api("freeaddrinfo", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        cpu.set_sp(cpu.sp() + 4);
        return 0;
    });

    // --- inet_addr(cp) ---
    // 1 arg
    api.register_api("inet_addr", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        uint32_t cp_addr = vmem.read32(cpu.sp() + 4);
        cpu.set_sp(cpu.sp() + 4);

        std::string ip_str = read_guest_string(vmem, cp_addr);

        // Parse dotted quad
        uint32_t a = 0, b = 0, c = 0, d = 0;
        if (std::sscanf(ip_str.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
            return (a & 0xFF) | ((b & 0xFF) << 8) | ((c & 0xFF) << 16) | ((d & 0xFF) << 24);
        }
        return 0xFFFFFFFF; // INADDR_NONE
    });

    // --- inet_ntoa(in) ---
    // 1 arg (struct in_addr passed by value = 4 bytes)
    api.register_api("inet_ntoa", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        uint32_t in_addr_val = vmem.read32(cpu.sp() + 4);
        cpu.set_sp(cpu.sp() + 4);

        std::string ip_str = ip_to_string(in_addr_val);

        // Write to scratch buffer
        uint32_t buf = alloc_scratch(vmem, 32);
        vmem.write(buf, ip_str.c_str(), ip_str.size() + 1);
        return buf;
    });

    // --- htons(hostshort) ---
    // 1 arg
    api.register_api("htons", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        uint16_t val = vmem.read32(cpu.sp() + 4) & 0xFFFF;
        cpu.set_sp(cpu.sp() + 4);
        return swap16(val);
    });

    // --- ntohs(netshort) ---
    // 1 arg
    api.register_api("ntohs", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        uint16_t val = vmem.read32(cpu.sp() + 4) & 0xFFFF;
        cpu.set_sp(cpu.sp() + 4);
        return swap16(val);
    });

    // --- htonl(hostlong) ---
    // 1 arg
    api.register_api("htonl", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        uint32_t val = vmem.read32(cpu.sp() + 4);
        cpu.set_sp(cpu.sp() + 4);
        return swap32(val);
    });

    // --- ntohl(netlong) ---
    // 1 arg
    api.register_api("ntohl", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        uint32_t val = vmem.read32(cpu.sp() + 4);
        cpu.set_sp(cpu.sp() + 4);
        return swap32(val);
    });

    // --- select(nfds, readfds, writefds, exceptfds, timeout) ---
    // 5 args
    api.register_api("select", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        cpu.set_sp(cpu.sp() + 20);
        return 1; // 1 socket ready
    });

    // --- ioctlsocket(s, cmd, argp) ---
    // 3 args
    api.register_api("ioctlsocket", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        cpu.set_sp(cpu.sp() + 12);
        return 0;
    });

    // --- setsockopt(s, level, optname, optval, optlen) ---
    // 5 args
    api.register_api("setsockopt", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        cpu.set_sp(cpu.sp() + 20);
        return 0;
    });

    // --- getsockopt(s, level, optname, optval, optlen) ---
    // 5 args
    api.register_api("getsockopt", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        cpu.set_sp(cpu.sp() + 20);
        return 0;
    });

    // --- shutdown(s, how) ---
    // 2 args
    api.register_api("shutdown", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        cpu.set_sp(cpu.sp() + 8);
        return 0;
    });

    // --- getpeername(s, name, namelen) ---
    // 3 args
    api.register_api("getpeername", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        uint32_t sock = vmem.read32(cpu.sp() + 4);
        uint32_t name_addr = vmem.read32(cpu.sp() + 8);
        uint32_t namelen_addr = vmem.read32(cpu.sp() + 12);
        cpu.set_sp(cpu.sp() + 12);

        auto it = s_sockets.find(sock);
        if (it != s_sockets.end() && name_addr) {
            // Write sockaddr_in
            uint16_t family = 2;
            vmem.write(name_addr, &family, 2);
            uint16_t port_be = swap16(it->second.remote_port);
            vmem.write(name_addr + 2, &port_be, 2);
            // Parse IP back to binary
            vmem.write32(name_addr + 4, 0x0100007F); // fallback
            if (namelen_addr) vmem.write32(namelen_addr, 16);
        }
        return 0;
    });

    // --- getsockname(s, name, namelen) ---
    // 3 args
    api.register_api("getsockname", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        uint32_t name_addr = vmem.read32(cpu.sp() + 8);
        uint32_t namelen_addr = vmem.read32(cpu.sp() + 12);
        cpu.set_sp(cpu.sp() + 12);
        if (name_addr) {
            uint16_t family = 2;
            vmem.write(name_addr, &family, 2);
            uint16_t port = 0;
            vmem.write(name_addr + 2, &port, 2);
            vmem.write32(name_addr + 4, 0x0100007F); // 127.0.0.1
            if (namelen_addr) vmem.write32(namelen_addr, 16);
        }
        return 0;
    });

    // --- sendto(s, buf, len, flags, to, tolen) ---
    // 6 args
    api.register_api("sendto", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        uint32_t len = vmem.read32(cpu.sp() + 12);
        cpu.set_sp(cpu.sp() + 24);
        return len;
    });

    // --- recvfrom(s, buf, len, flags, from, fromlen) ---
    // 6 args
    api.register_api("recvfrom", [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
        cpu.set_sp(cpu.sp() + 24);
        return 0; // No data
    });

} // end register_ws2_32_apis

} // namespace vx

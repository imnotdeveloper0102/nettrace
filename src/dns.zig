// dns.zig — Phân giải tên host sang IPv4 + tra ngược IP ra tên host.
// Dùng libc getaddrinfo / getnameinfo (qua std.c), tôn trọng /etc/resolv.conf
// và /etc/hosts nên chạy đúng cả trên Termux. Cần linkLibC (đã bật build.zig).
const std = @import("std");
const posix = std.posix;
const ip_mod = @import("ip.zig");

pub const DnsError = error{
    HostNotFound,
    TryAgain,
    NoAddress,
    SystemResources,
    Unexpected,
    OutOfMemory,
};

fn mapEai(rc: std.c.EAI) DnsError {
    return switch (rc) {
        .NONAME, .NODATA, .FAIL, .FAMILY, .SERVICE, .SOCKTYPE => error.HostNotFound,
        .AGAIN => error.TryAgain,
        .MEMORY => error.SystemResources,
        else => error.Unexpected,
    };
}

/// Phân giải `host` ("example.com", "localhost", "192.168.1.1") ra IPv4 đầu tiên.
pub fn resolveFirstIpv4(allocator: std.mem.Allocator, host: []const u8) DnsError![4]u8 {
    // IP literal thì khỏi hỏi DNS.
    if (ip_mod.parseIpv4(host)) |ip| {
        return ip;
    } else |_| {}

    const host_z = try allocator.alloc(u8, host.len + 1);
    defer allocator.free(host_z);
    @memcpy(host_z[0..host.len], host);
    host_z[host.len] = 0;
    const host_ptr: [*:0]const u8 = @ptrCast(host_z.ptr);

    var hints: posix.addrinfo = std.mem.zeroes(posix.addrinfo);
    hints.family = posix.AF.INET;
    hints.socktype = posix.SOCK.STREAM;

    var res: ?*posix.addrinfo = null;
    const rc = std.c.getaddrinfo(host_ptr, null, &hints, &res);
    if (@intFromEnum(rc) != 0) return mapEai(rc);
    defer std.c.freeaddrinfo(res.?);

    var cur: ?*posix.addrinfo = res;
    while (cur) |ai| {
        if (ai.family == posix.AF.INET and ai.addr != null) {
            const sin: *const posix.sockaddr.in = @ptrCast(@alignCast(ai.addr));
            const raw: [4]u8 = @bitCast(sin.addr);
            return raw;
        }
        cur = ai.next;
    }
    return error.NoAddress;
}

/// Tra ngược `ip` ra tên host (PTR). Trả về null khi không tra được —
/// tra ngược thất bại là chuyện bình thường, tool vẫn in IP.
pub fn reverseLookup(allocator: std.mem.Allocator, ip: [4]u8) ?[]u8 {
    const sin = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = 0,
        .addr = @bitCast(ip),
    };
    var host_buf: [256]u8 = undefined;
    const rc = std.c.getnameinfo(
        @ptrCast(&sin),
        @sizeOf(posix.sockaddr.in),
        &host_buf,
        host_buf.len,
        null,
        0,
        .{},
    );
    if (@intFromEnum(rc) != 0) return null;
    const len = std.mem.indexOfScalar(u8, &host_buf, 0) orelse host_buf.len;
    if (len == 0) return null;
    const out = allocator.dupe(u8, host_buf[0..len]) catch return null;
    return out;
}

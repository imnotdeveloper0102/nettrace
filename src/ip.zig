// ip.zig — IPv4: parse/format/phân loại. Hàm thuần, không đụng tới mạng.
// Lấy từ thư viện security-netsec (src/ip.zig), rút gọn cho tool nettrace.
const std = @import("std");

pub const IpError = error{InvalidIp};

/// "192.168.1.10" -> .{ 192, 168, 1, 10 }. Chặt: đủ 4 octet, mỗi octet 0-255.
pub fn parseIpv4(text: []const u8) IpError![4]u8 {
    var out: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, text, '.');
    var i: usize = 0;
    while (it.next()) |part| {
        if (i >= 4) return error.InvalidIp;
        if (part.len == 0 or part.len > 3) return error.InvalidIp;
        var v: u16 = 0;
        for (part) |c| {
            if (c < '0' or c > '9') return error.InvalidIp;
            v = v * 10 + (@as(u16, c) - '0');
            if (v > 255) return error.InvalidIp;
        }
        out[i] = @intCast(v);
        i += 1;
    }
    if (i != 4) return error.InvalidIp;
    return out;
}

/// [4]u8 -> "192.168.1.10" (ghi vào buf do người gọi cấp, tối thiểu 16 byte).
pub fn formatIpv4(ip: [4]u8, buf: *[16]u8) []u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch unreachable;
}

pub fn isLoopback(ip: [4]u8) bool {
    return ip[0] == 127;
}

pub fn isPrivate(ip: [4]u8) bool {
    if (ip[0] == 10) return true;
    if (ip[0] == 172 and ip[1] >= 16 and ip[1] <= 31) return true;
    if (ip[0] == 192 and ip[1] == 168) return true;
    return false;
}

/// Kiểu của một địa chỉ, để in ra cho dễ đọc.
pub fn classify(ip: [4]u8) []const u8 {
    if (ip[0] == 0 and ip[1] == 0 and ip[2] == 0 and ip[3] == 0) return "unspecified";
    if (isLoopback(ip)) return "loopback";
    if (isPrivate(ip)) return "private";
    if (ip[0] == 169 and ip[1] == 254) return "link-local";
    return "public";
}

test "parseIpv4" {
    const t = std.testing;
    try t.expectEqual([4]u8{ 192, 168, 1, 10 }, try parseIpv4("192.168.1.10"));
    try t.expectEqual([4]u8{ 127, 0, 0, 1 }, try parseIpv4("127.0.0.1"));
    try t.expectError(error.InvalidIp, parseIpv4("256.1.1.1"));
    try t.expectError(error.InvalidIp, parseIpv4("192.168.1"));
    try t.expectError(error.InvalidIp, parseIpv4("abc.def.1.1"));
}

test "classify" {
    const t = std.testing;
    try t.expectEqualStrings("loopback", classify(.{ 127, 0, 0, 1 }));
    try t.expectEqualStrings("private", classify(.{ 192, 168, 0, 1 }));
    try t.expectEqualStrings("public", classify(.{ 8, 8, 8, 8 }));
}

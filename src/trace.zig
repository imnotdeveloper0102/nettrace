// trace.zig — Lõi truy vết: UDP và TCP traceroute, không cần root.
//
// Cách hoạt động (Linux / Termux, không cần raw socket):
//   * Mỗi hop gửi một gói với TTL tăng dần 1, 2, 3, ...
//   * Router ở hop đó hết TTL sẽ gửi lại ICMP "Time Exceeded".
//     Kernel Linux đưa ICMP này vào *error queue* của socket khi bật
//     IP_RECVERR, đọc bằng recvmsg(MSG_ERRQUEUE) — không cần socket raw,
//     không cần root. Địa chỉ router nằm trong msg_name / sau
//     struct sock_extended_err của cmsg.
//   * UDP: gói tới port 33434+TTL (kiểu traceroute cổ điển). Đích đến
//     trả ICMP "Port Unreachable" -> biết đã tới đích.
//   * TCP: connect tới port --port (mặc định 80) với TTL giới hạn.
//     Connect thành công / bị từ chối (RST) nghĩa là đã tới đích;
//     Time Exceeded ở giữa đường vẫn bắt được qua error queue.
//     TCP xuyên firewall/NAT tốt hơn UDP, nên là mode mặc định.
//
// Giới hạn thật (đã kiểm chứng trên máy này):
//   * Sandbox chặn UDP sendto (EPERM) và chặn socket raw (ping cũng
//     không chạy). Trên máy này chỉ TCP chạy được, và TCP ra Internet
//     bị chặn/chuyển hướng nên "tới đích ở hop 1" là giả. Trên máy thật
//     / Termux mới đo được đường đi thật — xem README.
const std = @import("std");
const posix = std.posix;

// Hằng số Linux không có sẵn trong std.posix của Zig 0.17.1.
// Giá trị lấy từ <netinet/in.h> / <sys/socket.h> của glibc.
const sol_ip: i32 = 0;
const ip_ttl: u32 = 2;
const ip_recverr: u32 = 11;
const msg_errqueue: u32 = 0x2000;
const msg_dontwait: u32 = 0x40;
const icmp_time_exceeded: u8 = 11;
const icmp_dest_unreach: u8 = 3;
const so_ee_origin_icmp: u8 = 2;

/// struct sock_extended_err trong <linux/errqueue.h>.
const SockExtendedErr = extern struct {
    ee_errno: u32,
    ee_origin: u8,
    ee_type: u8,
    ee_code: u8,
    ee_pad: u8,
    ee_info: u32,
    ee_data: u32,
};

pub const Mode = enum {
    tcp,
    udp,

    pub fn parse(text: []const u8) ?Mode {
        if (std.mem.eql(u8, text, "tcp")) return .tcp;
        if (std.mem.eql(u8, text, "udp")) return .udp;
        return null;
    }
};

pub const ProbeStatus = enum {
    timeout, // không có phản hồi trong timeout
    time_exceeded, // router giữa đường hết TTL, đã biết IP hop
    dest_unreach, // đích trả ICMP unreachable (UDP) — đã tới đích
    reached, // TCP connect thành công — đã tới đích
    refused, // TCP bị RST — đã tới đích, port đóng
    denied, // bị cấm (EPERM): sandbox / không có quyền
    err, // lỗi socket khác

    pub fn isAtTarget(self: ProbeStatus) bool {
        return self == .reached or self == .refused or self == .dest_unreach;
    }
};

pub const ProbeResult = struct {
    status: ProbeStatus,
    ip: ?[4]u8 = null,
    rtt_ms: ?f64 = null,
};

pub const TraceOptions = struct {
    mode: Mode = .tcp,
    port: u16 = 80,
    max_hops: u8 = 30,
    timeout_ms: i32 = 1000,
    probes: u8 = 3,
};

/// Port UDP cổ điển của traceroute: 33434 + TTL.
pub fn baseUdpPort(ttl: u8) u16 {
    return @as(u16, 33434) + ttl;
}

fn closeFd(fd: posix.socket_t) void {
    _ = posix.system.close(fd);
}

fn setOptInt(fd: posix.socket_t, level: i32, optname: u32, val: i32) void {
    const bytes = std.mem.asBytes(&val);
    posix.setsockopt(fd, level, optname, bytes) catch {};
}

fn setTtl(fd: posix.socket_t, ttl: u8) void {
    setOptInt(fd, sol_ip, ip_ttl, ttl);
}

fn setRecvErr(fd: posix.socket_t) void {
    setOptInt(fd, sol_ip, ip_recverr, 1);
}

fn setRecvTimeout(fd: posix.socket_t, timeout_ms: i32) void {
    const tv = posix.timeval{
        .sec = @divTrunc(timeout_ms, 1000),
        .usec = @mod(timeout_ms, 1000) * 1000,
    };
    const bytes = std.mem.asBytes(&tv);
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, bytes) catch {};
}

fn monotonicNs() i128 {
    var ts: std.c.timespec = undefined;
    // CLOCK_MONOTONIC = 1 trên Linux.
    if (std.c.clock_gettime(@enumFromInt(1), &ts) != 0) return 0;
    return @as(i128, ts.sec) * 1_000_000_000 + ts.nsec;
}

fn rttMs(start_ns: i128) f64 {
    return @as(f64, @floatFromInt(monotonicNs() - start_ns)) / 1_000_000.0;
}

/// Đọc một lần error queue (không chờ). Trả về null khi không có lỗi nào
/// đang chờ. Khi có ICMP, trả về ProbeResult với IP của router/đích.
fn readErrQueue(fd: posix.socket_t, start_ns: i128) ?ProbeResult {
    var data_buf: [512]u8 = undefined;
    var ctrl_buf: [512]u8 align(8) = undefined;
    var from: posix.sockaddr.in = std.mem.zeroes(posix.sockaddr.in);
    var iov = [_]posix.iovec{.{
        .base = &data_buf,
        .len = data_buf.len,
    }};
    var msg = posix.msghdr{
        .name = @ptrCast(&from),
        .namelen = @sizeOf(posix.sockaddr.in),
        .iov = &iov,
        .iovlen = 1,
        .control = &ctrl_buf,
        .controllen = ctrl_buf.len,
        .flags = 0,
    };
    const rc = posix.system.recvmsg(fd, &msg, msg_errqueue | msg_dontwait);
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => return null,
    }

    const rtt = rttMs(start_ns);
    // Ưu tiên msg_name: kernel ghi địa chỉ người gửi ICMP vào đó.
    var hop_ip: ?[4]u8 = null;
    if (msg.namelen >= @sizeOf(posix.sockaddr.in) and from.family == posix.AF.INET) {
        hop_ip = @bitCast(from.addr);
    }
    // Phân tích cmsg đầu tiên: SOL_IP / IP_RECVERR -> sock_extended_err.
    if (msg.controllen >= @sizeOf(posix.cmsghdr) + @sizeOf(SockExtendedErr)) {
        const cmsg: *const posix.cmsghdr = @ptrCast(@alignCast(&ctrl_buf));
        if (cmsg.level == sol_ip and cmsg.type == ip_recverr) {
            const ee_off = @sizeOf(posix.cmsghdr);
            const ee: *const SockExtendedErr = @ptrCast(@alignCast(ctrl_buf[ee_off..].ptr));
            if (hop_ip == null and ee.ee_origin == so_ee_origin_icmp) {
                // Sau ee là sockaddr của router gửi ICMP.
                const off_off = ee_off + @sizeOf(SockExtendedErr);
                if (msg.controllen >= off_off + @sizeOf(posix.sockaddr.in)) {
                    const offender: *const posix.sockaddr.in = @ptrCast(@alignCast(ctrl_buf[off_off..].ptr));
                    if (offender.family == posix.AF.INET) {
                        hop_ip = @bitCast(offender.addr);
                    }
                }
            }
            if (ee.ee_type == icmp_time_exceeded) {
                return .{ .status = .time_exceeded, .ip = hop_ip, .rtt_ms = rtt };
            }
            if (ee.ee_type == icmp_dest_unreach) {
                return .{ .status = .dest_unreach, .ip = hop_ip, .rtt_ms = rtt };
            }
            // ICMP khác (vd redirect): vẫn biết IP hop, coi như time_exceeded.
            if (hop_ip != null) {
                return .{ .status = .time_exceeded, .ip = hop_ip, .rtt_ms = rtt };
            }
        }
    }
    if (hop_ip != null) {
        return .{ .status = .time_exceeded, .ip = hop_ip, .rtt_ms = rtt };
    }
    return null;
}

fn waitReadable(fd: posix.socket_t, timeout_ms: i32) bool {
    var pfd = [_]posix.pollfd{.{
        .fd = fd,
        .events = posix.POLL.IN,
        .revents = 0,
    }};
    const n = posix.poll(&pfd, timeout_ms) catch return false;
    return n > 0;
}

/// Một probe UDP tới `target`, TTL = `ttl`, port đích 33434+ttl.
pub fn udpProbe(target: [4]u8, ttl: u8, timeout_ms: i32) ProbeResult {
    const flags: u32 = posix.SOCK.DGRAM | posix.SOCK.CLOEXEC;
    const rc = posix.system.socket(posix.AF.INET, flags, 17);
    if (posix.errno(rc) != .SUCCESS) return .{ .status = .err };
    const fd: posix.socket_t = @intCast(rc);
    defer closeFd(fd);

    setRecvErr(fd);
    setTtl(fd, ttl);
    setRecvTimeout(fd, timeout_ms);

    var dest = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, baseUdpPort(ttl)),
        .addr = @bitCast(target),
    };
    const payload = "nettrace";
    const start_ns = monotonicNs();
    const src = posix.system.sendto(fd, payload.ptr, payload.len, 0, @ptrCast(&dest), @sizeOf(posix.sockaddr.in));
    switch (posix.errno(src)) {
        .SUCCESS => {},
        .ACCES, .PERM => return .{ .status = .denied, .rtt_ms = rttMs(start_ns) },
        else => return .{ .status = .err },
    }

    // Chờ ICMP về error queue (hoặc timeout).
    if (waitReadable(fd, timeout_ms)) {
        if (readErrQueue(fd, start_ns)) |r| return r;
    } else {
        // Hết timeout nhưng ICMP có thể vừa về: thử đọc error queue một lần.
        if (readErrQueue(fd, start_ns)) |r| return r;
    }
    return .{ .status = .timeout };
}

/// Một probe TCP tới `target:port`, TTL = `ttl`.
pub fn tcpProbe(target: [4]u8, port: u16, ttl: u8, timeout_ms: i32) ProbeResult {
    const flags: u32 = posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC;
    const rc = posix.system.socket(posix.AF.INET, flags, 0);
    if (posix.errno(rc) != .SUCCESS) return .{ .status = .err };
    const fd: posix.socket_t = @intCast(rc);
    defer closeFd(fd);

    setRecvErr(fd);
    setTtl(fd, ttl);
    setRecvTimeout(fd, timeout_ms);

    var dest = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = @bitCast(target),
    };
    const start_ns = monotonicNs();
    const crc = posix.system.connect(fd, @ptrCast(&dest), @sizeOf(posix.sockaddr.in));
    switch (posix.errno(crc)) {
        .SUCCESS => return .{ .status = .reached, .ip = target, .rtt_ms = rttMs(start_ns) },
        .AGAIN, .INPROGRESS => {},
        .CONNREFUSED => return .{ .status = .refused, .ip = target, .rtt_ms = rttMs(start_ns) },
        .ACCES, .PERM => return .{ .status = .denied },
        else => {
            if (readErrQueue(fd, start_ns)) |r| return r;
            return .{ .status = .err };
        },
    }

    // Đang connect: poll chờ writable trong timeout.
    var pfd = [_]posix.pollfd{.{
        .fd = fd,
        .events = posix.POLL.OUT,
        .revents = 0,
    }};
    const n = posix.poll(&pfd, timeout_ms) catch {
        if (readErrQueue(fd, start_ns)) |r| return r;
        return .{ .status = .err };
    };
    if (n == 0) {
        if (readErrQueue(fd, start_ns)) |r| return r;
        return .{ .status = .timeout };
    }
    // Poll báo writable cả khi connect thất bại: đọc SO_ERROR mới biết thật.
    var so_error: i32 = 0;
    var optlen: posix.socklen_t = @sizeOf(i32);
    const grc = posix.system.getsockopt(fd, posix.SOL.SOCKET, posix.SO.ERROR, @ptrCast(&so_error), &optlen);
    if (posix.errno(grc) != .SUCCESS) {
        if (readErrQueue(fd, start_ns)) |r| return r;
        return .{ .status = .err };
    }
    if (so_error == 0) {
        return .{ .status = .reached, .ip = target, .rtt_ms = rttMs(start_ns) };
    }
    // ECONNREFUSED (111) = đã tới đích, port đóng.
    if (so_error == 111) {
        return .{ .status = .refused, .ip = target, .rtt_ms = rttMs(start_ns) };
    }
    // Lỗi khác: có thể là ICMP Time Exceeded / Unreachable trong error queue.
    if (readErrQueue(fd, start_ns)) |r| return r;
    if (so_error == 110) return .{ .status = .timeout }; // ETIMEDOUT
    return .{ .status = .err };
}

pub fn probe(target: [4]u8, opts: TraceOptions, ttl: u8) ProbeResult {
    return switch (opts.mode) {
        .tcp => tcpProbe(target, opts.port, ttl, opts.timeout_ms),
        .udp => udpProbe(target, ttl, opts.timeout_ms),
    };
}

test "baseUdpPort" {
    const t = std.testing;
    try t.expectEqual(@as(u16, 33435), baseUdpPort(1));
    try t.expectEqual(@as(u16, 33464), baseUdpPort(30));
}

test "parseMode" {
    const t = std.testing;
    try t.expectEqual(Mode.tcp, Mode.parse("tcp").?);
    try t.expectEqual(Mode.udp, Mode.parse("udp").?);
    try t.expect(Mode.parse("icmp") == null);
}

test "isAtTarget" {
    const t = std.testing;
    try t.expect(ProbeStatus.reached.isAtTarget());
    try t.expect(ProbeStatus.refused.isAtTarget());
    try t.expect(ProbeStatus.dest_unreach.isAtTarget());
    try t.expect(!ProbeStatus.time_exceeded.isAtTarget());
    try t.expect(!ProbeStatus.timeout.isAtTarget());
}

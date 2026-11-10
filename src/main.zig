// nettrace — Tool CLI truy vết mạng (traceroute) viết bằng Zig.
//
// Cách dùng:
//   nettrace <host> [--mode tcp|udp] [--port 80] [--max-hops 30]
//                    [--timeout 1000] [--probes 3] [--no-resolve]
//   nettrace example.com
//   nettrace 8.8.8.8 --mode udp --probes 1
//   nettrace 192.168.1.1 --mode tcp --port 443 -q 1
//   nettrace localhost --mode tcp -q 1
//
// Chỉ truy vết host của mình, mạng của mình, hoặc host công khai cho
// phép như scanme.nmap.org / example.com. Không dùng để dò mạng người khác.
const std = @import("std");
const trace = @import("trace.zig");
const dns = @import("dns.zig");
const ip_mod = @import("ip.zig");

const version = "0.1.0";

// Bionic trên ARM64 yêu cầu TLS alignment >= 64, musl mặc định chỉ 8
// nên binary musl chạy trên Termux bị lỗi
// "executable's TLS segment is underaligned: alignment is 8".
// Biến threadlocal align 64 này ép linker nâng PT_TLS lên 64.
export threadlocal var android_tls_align_fix: [64]u8 align(64) = std.mem.zeroes([64]u8);

fn printUsage(prog: []const u8) void {
    std.debug.print(
        \\nettrace {s} — truy vết mạng (traceroute) bằng Zig, không cần root
        \\
        \\Dùng: {s} <host> [tùy chọn]
        \\
        \\Tùy chọn:
        \\  --mode tcp|udp     Kiểu probe (mặc định tcp: connect port --port,
        \\                     xuyên firewall tốt hơn; udp: kiểu traceroute
        \\                     cổ điển, port đích 33434+TTL)
        \\  --port, -p <port>  Port TCP để probe (mặc định 80)
        \\  --max-hops, -m N   Số hop tối đa (mặc định 30, 1..64)
        \\  --timeout, -w ms   Timeout mỗi probe, mili-giây (mặc định 1000)
        \\  --probes, -q N     Số probe mỗi hop (mặc định 3, 1..5)
        \\  --no-resolve, -n   Không tra ngược tên host (chỉ in IP)
        \\  --help, -h         In hướng dẫn này
        \\
        \\Ví dụ:
        \\  {s} example.com
        \\  {s} 8.8.8.8 --mode udp -q 1
        \\  {s} localhost --mode tcp -q 1
        \\
    , .{ version, prog, prog, prog, prog });
}

const Args = struct {
    host: []const u8 = "",
    opts: trace.TraceOptions = .{},
    resolve: bool = true,
    help: bool = false,
};

fn parseArgs(args: []const []const u8) !Args {
    var out = Args{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
            out.help = true;
        } else if (std.mem.eql(u8, a, "--mode")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            out.opts.mode = trace.Mode.parse(args[i]) orelse return error.BadMode;
        } else if (std.mem.startsWith(u8, a, "--mode=")) {
            out.opts.mode = trace.Mode.parse(a["--mode=".len..]) orelse return error.BadMode;
        } else if (std.mem.eql(u8, a, "--port") or std.mem.eql(u8, a, "-p")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            out.opts.port = std.fmt.parseInt(u16, args[i], 10) catch return error.BadPort;
            if (out.opts.port == 0) return error.BadPort;
        } else if (std.mem.eql(u8, a, "--max-hops") or std.mem.eql(u8, a, "-m")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            const v = std.fmt.parseInt(u32, args[i], 10) catch return error.BadMaxHops;
            if (v < 1 or v > 64) return error.BadMaxHops;
            out.opts.max_hops = @intCast(v);
        } else if (std.mem.eql(u8, a, "--timeout") or std.mem.eql(u8, a, "-w")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            const v = std.fmt.parseInt(i32, args[i], 10) catch return error.BadTimeout;
            if (v < 100 or v > 10000) return error.BadTimeout;
            out.opts.timeout_ms = v;
        } else if (std.mem.eql(u8, a, "--probes") or std.mem.eql(u8, a, "-q")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            const v = std.fmt.parseInt(u32, args[i], 10) catch return error.BadProbes;
            if (v < 1 or v > 5) return error.BadProbes;
            out.opts.probes = @intCast(v);
        } else if (std.mem.eql(u8, a, "--no-resolve") or std.mem.eql(u8, a, "-n")) {
            out.resolve = false;
        } else if (std.mem.startsWith(u8, a, "-")) {
            return error.UnknownOption;
        } else if (out.host.len == 0) {
            out.host = a;
        } else {
            return error.TooManyHosts;
        }
    }
    return out;
}

pub fn main(init: std.process.Init.Minimal) !void {
    // Giữ biến TLS align ở trên, không cho linker loại bỏ nó:
    // ghi 1 byte thật vào nó rồi đọc lại.
    android_tls_align_fix[0] = 1;
    if (android_tls_align_fix[0] != 1) return error.TlsAlignFixFailed;
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const args = try init.args.toSlice(arena.allocator());

    const parsed = parseArgs(args) catch |err| {
        std.debug.print("Lỗi tham số: {t}\n", .{err});
        printUsage(args[0]);
        return;
    };
    if (parsed.help or parsed.host.len == 0) {
        printUsage(args[0]);
        return;
    }
    const opts = parsed.opts;

    const target = dns.resolveFirstIpv4(alloc, parsed.host) catch |err| {
        std.debug.print("Không phân giải được {s}: {t}\n", .{ parsed.host, err });
        return;
    };
    var target_buf: [16]u8 = undefined;
    const target_text = ip_mod.formatIpv4(target, &target_buf);
    std.debug.print("nettrace tới {s} ({s}, {s}), tối đa {d} hop, mode {s}", .{
        parsed.host, target_text, ip_mod.classify(target), opts.max_hops, @tagName(opts.mode),
    });
    if (opts.mode == .tcp) {
        std.debug.print(", port {d}", .{opts.port});
    }
    std.debug.print(", timeout {d}ms, {d} probe/hop\n", .{ opts.timeout_ms, opts.probes });

    var reached = false;
    var ttl: u8 = 1;
    while (ttl <= opts.max_hops and !reached) : (ttl += 1) {
        std.debug.print("{d:>2}  ", .{ttl});
        var hop_ip: ?[4]u8 = null;
        var hop_name: ?[]u8 = null;
        var any_reply = false;
        var p: u8 = 0;
        while (p < opts.probes) : (p += 1) {
            const r = trace.probe(target, opts, ttl);
            switch (r.status) {
                .timeout => std.debug.print(" *", .{}),
                .denied => std.debug.print(" !X (bị cấm)", .{}),
                .err => std.debug.print(" !E", .{}),
                else => {
                    any_reply = true;
                    if (r.ip) |found| {
                        if (hop_ip == null) hop_ip = found;
                        if (r.status.isAtTarget()) reached = true;
                    }
                    if (r.rtt_ms) |ms| {
                        std.debug.print(" {d:.1}ms", .{ms});
                    } else {
                        std.debug.print(" ?", .{});
                    }
                },
            }
        }
        // In IP / tên host của hop (lấy từ probe đầu tiên có IP).
        if (hop_ip) |found| {
            var ip_buf: [16]u8 = undefined;
            const ip_text = ip_mod.formatIpv4(found, &ip_buf);
            if (parsed.resolve) {
                // Dùng arena để tên host tự giải phóng khi main kết thúc,
                // tránh DebugAllocator báo leak.
                hop_name = dns.reverseLookup(arena.allocator(), found);
            }
            if (hop_name) |name| {
                std.debug.print("  {s} ({s})", .{ name, ip_text });
            } else {
                std.debug.print("  {s}", .{ip_text});
            }
            if (std.mem.eql(u8, &found, &target)) reached = true;
        } else if (!any_reply) {
            std.debug.print("  (không phản hồi)", .{});
        }
        std.debug.print("\n", .{});
        // Hết 3 hop liên tiếp không phản hồi thì vẫn chạy tiếp như traceroute
        // thật — không dừng sớm, để cậu thấy đủ đường đi.
    }

    if (reached) {
        std.debug.print("Đã tới đích {s} ({s}).\n", .{ parsed.host, target_text });
    } else {
        std.debug.print("Hết {d} hop mà chưa tới đích (có thể đích chặn probe hoặc đường đi dài hơn).\n", .{opts.max_hops});
    }
    if (opts.mode == .udp) {
        std.debug.print("Gợi ý: nếu UDP bị chặn, thử lại với --mode tcp --port 80.\n", .{});
    }
}

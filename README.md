# nettrace — Tool CLI truy vết mạng bằng Zig

Traceroute viết bằng Zig 0.17.1, **không cần root**, chạy được trên Linux và
Termux (Android ARM64). Một file binary duy nhất, không cần runtime.

## Cách chạy

```sh
./nettrace <host> [tùy chọn]
./nettrace example.com
./nettrace 8.8.8.8 --mode udp -q 1
./nettrace 192.168.1.1 --mode tcp --port 443 -q 1
./nettrace localhost --mode tcp -q 1
```

### Tùy chọn

| Tùy chọn | Mặc định | Nghĩa |
| --- | --- | --- |
| `--mode tcp\|udp` | `tcp` | Kiểu probe. TCP connect port `--port`, xuyên firewall/NAT tốt hơn. UDP là kiểu traceroute cổ điển, port đích `33434+TTL` |
| `--port, -p` | `80` | Port TCP để probe |
| `--max-hops, -m` | `30` | Số hop tối đa (1–64) |
| `--timeout, -w` | `1000` ms | Timeout mỗi probe (100–10000 ms) |
| `--probes, -q` | `3` | Số probe mỗi hop (1–5) |
| `--no-resolve, -n` | — | Không tra ngược tên host, chỉ in IP |
| `--help, -h` | — | In hướng dẫn |

Ví dụ kết quả (localhost, chạy thật):

```
nettrace tới localhost (127.0.0.1, loopback), tối đa 2 hop, mode tcp, port 80, timeout 500ms, 3 probe/hop
 1   0.1ms 0.1ms 0.0ms  localhost (127.0.0.1)
Đã tới đích localhost (127.0.0.1).
```

## Cách nó hoạt động (không cần root)

Mỗi hop gửi một gói với TTL tăng dần 1, 2, 3, … Router ở hop đó hết TTL sẽ
gửi lại ICMP “Time Exceeded”. Kernel Linux đưa ICMP này vào *error queue*
của socket khi bật `IP_RECVERR`, đọc bằng `recvmsg(MSG_ERRQUEUE)` — không
cần socket raw, không cần root. Địa chỉ router nằm trong `msg_name` / sau
struct `sock_extended_err` của cmsg.

- **UDP:** gói tới port `33434+TTL`. Đích trả ICMP “Port Unreachable” là
  biết đã tới đích.
- **TCP:** connect tới port `--port` với TTL giới hạn. Connect thành công /
  bị RST (port đóng) nghĩa là đã tới đích; Time Exceeded giữa đường vẫn bắt
  được qua error queue.

## Build từ source

```sh
zig build            # binary x86_64 ở zig-out/bin/nettrace
zig build test       # unit test
```

Cần Zig **0.17.1** (code dùng API của bản này: `std.posix`, `std.c`,
`clock_gettime` qua libc). Toolchain dùng ở đây:
`~/workspace/tools/zig-x86_64-linux-0.17.1/zig`.

### Bản cho Termux / điện thoại ARM64

Target `aarch64-linux-android` cần NDK nên Zig không tự cấp libc được.
Bản ARM64 đã build sẵn bằng target `aarch64-linux-musl` (static, không
phụ thuộc libc), chạy được trên kernel Linux ARM64 của Android:

```sh
zig build -Dtarget=aarch64-linux-musl -Doptimize=ReleaseSafe \
  --prefix zig-out-aarch64-musl
# binary: zig-out-aarch64-musl/bin/nettrace (4,5 MB, ARM aarch64, static)
```

Chép sang điện thoại rồi chạy trong Termux (đặt ở thư mục home, **không**
đặt ở `/sdcard` vì đó là `noexec`):

```sh
cp nettrace ~/nettrace
chmod +x ~/nettrace
~/nettrace example.com
~/nettrace 8.8.8.8 --mode udp -q 1
```

## Kết quả kiểm chứng (2026-11-10, đã chạy thật)

| Lệnh | Kết quả |
| --- | --- |
| `zig build test` | Pass |
| `nettrace --help` | In đúng hướng dẫn |
| `nettrace localhost --mode tcp -q 3` | Hop 1: `0.1ms 0.1ms 0.0ms localhost (127.0.0.1)`, đã tới đích — đúng |
| `nettrace 127.0.0.1 --mode tcp -p 443 -q 1` | Hop 1: `0.1ms 127.0.0.1`, đã tới đích — đúng |
| `nettrace example.com --mode tcp` (trên máy này) | “Tới đích ở hop 1, 0.1ms” — **là giả, xem dưới** |
| `nettrace 8.8.8.8 --mode udp` (trên máy này) | `!X (bị cấm)` cả 3 hop — sandbox chặn UDP |

## Giới hạn thật — đọc trước khi tin kết quả

Mạng ra ngoài của máy build này **không phải mạng thật**, đã kiểm chứng
bằng Python trước khi viết tool:

- DNS bị chuyển hướng: `example.com` phân giải ra `198.18.30.241`,
  tên miền không tồn tại cũng phân giải ra `198.18.30.242`.
- TCP ra Internet bị chặn/chuyển hướng: connect tới `8.8.8.8:80` thành
  công trong 0,1 ms ở TTL = 1 — không thể là đường đi thật.
- UDP `sendto` bị chặn hoàn toàn (`EPERM`), socket raw cũng bị chặn
  (`ping` báo `Operation not permitted`).

Vì vậy **kết quả trace ra Internet trên máy này không đáng tin** — tool
chạy đúng, nhưng mạng chặn nên nó chỉ thấy “đích ở hop 1”. Muốn đo đường
đi thật, chạy bản ARM64 trên Termux / máy thật của cậu, nơi UDP và TCP
không bị chặn như ở đây.

## Cấu trúc

```
nettrace/
  build.zig / build.zig.zon   build Zig 0.17.1
  src/main.zig                CLI: parse tham số, in từng hop
  src/trace.zig               lõi probe UDP/TCP + đọc error queue
  src/dns.zig                 getaddrinfo (xuôi) + getnameinfo (ngược)
  src/ip.zig                  parse/format/phân loại IPv4
  README.md
```

Chỉ truy vết host của mình, mạng của mình, hoặc host công khai cho phép
như `scanme.nmap.org` / `example.com`. Không dùng để dò mạng người khác
khi chưa được phép.

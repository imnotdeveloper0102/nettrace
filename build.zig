const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const exe = b.addExecutable(.{
        .name = "nettrace",
        .root_module = exe_mod,
    });
    // Android / Termux bắt buộc PIE (ELF Type DYN, e_type 3).
    // Bản static musl mặc định ra EXEC (e_type 2) nên linker Android
    // báo "has unexpected e_type: 2" và không chạy được.
    exe.pie = true;
    b.installArtifact(exe);

    const test_step = b.step("test", "Chạy unit test");
    for ([_][]const u8{ "src/trace.zig", "src/ip.zig" }) |path| {
        const test_mod = b.createModule(.{
            .root_source_file = b.path(path),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        const unit_tests = b.addTest(.{ .root_module = test_mod });
        test_step.dependOn(&b.addRunArtifact(unit_tests).step);
    }
}

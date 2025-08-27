const std = @import("std");
const builtin = @import("builtin");

const log = std.log.scoped(.pod);
const asBytes = std.mem.asBytes;
const Allocator = std.mem.Allocator;

pub const VERSION = 2;
pub const Blake2 = std.crypto.hash.blake2.Blake2s;

const Magic = packed struct(u128) {
    little_endian: bool,
    version: u7,
    hash: u120,

    const Hasher = Blake2(128);

    fn init(comptime T: type) Magic {
        comptime {
            var self: Magic = undefined;
            if (@hasDecl(T, "POD_MAGIC")) {
                self.hash = @field(T, "POD_MAGIC");
            } else {
                var hasher = Hasher.init(.{});
                update(&hasher, T);
                hasher.final(asBytes(&self));
            }

            self.little_endian = builtin.cpu.arch.endian() == .little;
            self.version = VERSION;
            return self;
        }
    }

    fn update(hasher: *Hasher, comptime T: type) void {
        comptime switch (@typeInfo(T)) {
            .@"struct" => |info| {
                hasher.update("struct");
                hasher.update(@tagName(info.layout));
                if (info.backing_integer) |Int| {
                    const bits: u8 = @bitSizeOf(Int);
                    hasher.update(asBytes(&bits));
                }
                for (info.fields) |f| {
                    hasher.update(f.name);
                    update(hasher, f.type);
                }
            },
            .@"union" => |info| {
                hasher.update("union");
                hasher.update(@tagName(info.layout));
                if (info.tag_type) |Tag| {
                    update(hasher, Tag);
                }
                for (info.fields) |f| {
                    hasher.update(f.name);
                    update(hasher, f.type);
                }
            },
            .@"enum" => |info| {
                hasher.update("enum");
                if (info.is_exhaustive)
                    hasher.update("exhaustive");
                for (info.fields) |f| {
                    hasher.update(f.name);
                }
            },
            .optional => |info| {
                hasher.update("?");
                update(hasher, info.child);
            },
            .pointer => |info| {
                const prefix = switch (info.size) {
                    .c => "[*c]",
                    .one => "*",
                    else => std.fmt.comptimePrint("[{s}{s}]", .{
                        if (info.size == .many) "*" else "",
                        if (info.sentinel()) |_| ":any" else "",
                    }),
                };
                hasher.update(prefix);

                if (info.is_allowzero)
                    hasher.update("allowzero");
                if (info.is_const)
                    hasher.update("const");
                if (info.is_volatile)
                    hasher.update("volatile");
                update(hasher, info.child);
            },
            .array => |info| {
                const prefix = std.fmt.comptimePrint("[{d}]", .{info.len});
                hasher.update(prefix);
                update(hasher, info.child);
            },
            .vector => |info| {
                const prefix = std.fmt.comptimePrint("<{d}>", .{info.len});
                hasher.update(prefix);
                update(hasher, info.child);
            },
            else => hasher.update(@typeName(T)),
        };
    }
};

pub fn Pod(comptime T: type) type {
    return struct {
        const Self = @This();

        magic: Magic = Magic.init(T),
        value: T,
    };
}

const Map = std.AutoHashMap(usize, usize);

pub const ALIGNMENT = 16;

fn Slice(comptime T: type) type {
    const info = @typeInfo(T).pointer;
    return if (info.is_const)
        []const align(info.alignment) info.child
    else
        []align(info.alignment) info.child;
}

fn Pointer(comptime T: type) type {
    const info = @typeInfo(T).pointer;
    return if (info.is_const)
        [*]const align(info.alignment) info.child
    else
        [*]align(info.alignment) info.child;
}

fn Context(comptime precompute: bool) type {
    return struct {
        const Self = @This();

        data:
            if (precompute) void
            else []align(ALIGNMENT) u8,
        used: *usize,
        offset: usize = 0,

        fn F(comptime fmt: []const u8) []const u8 {
            if (precompute)
                return "precompute." ++ fmt;
            return fmt;
        }

        fn write(self: Self, comptime T: type, value: T, resolved: *Map) !void {
            var copy: T = value;
            try self.fixup(T, &copy, resolved);

            if (precompute)
                return;

            const copy_bytes = asBytes(&copy);
            const value_bytes = self.data[self.offset..][0..@sizeOf(T)];
            @memcpy(value_bytes, copy_bytes);
            log.debug("write({s}): {any} -> data[{d}..{d}]: {any}", .{
                @typeName(T),
                value,
                self.offset,
                self.offset + @sizeOf(T),
                value_bytes,
            });
        }

        fn read(self: Self, comptime T: type, ref: *T) void {
            if (precompute)
                unreachable;

            const at = @intFromPtr(ref) - @intFromPtr(self.data.ptr);
            log.debug("read: {s}: from buffer[{d}..{d}]: {any}", .{
                @typeName(T),
                at,
                at + @sizeOf(T),
                self.data[at..][0..@sizeOf(T)],
            });

            self.rfixup(T, ref);
        }

        fn fixup(self: Self, comptime T: type, ref: *T, resolved: *Map) !void {
            switch (@typeInfo(T)) {
                .@"struct" => |info| {
                    if (info.layout == .@"packed")
                        return;

                    inline for (info.fields) |f| {
                        const fptr = &@field(ref.*, f.name);
                        log.debug(F("fixup: {s}.{s}: {any}"), .{
                            @typeName(T),
                            f.name,
                            @field(ref.*, f.name),
                        });
                        try self.fixup(f.type, fptr, resolved);
                    }
                },
                .@"union" => |info| {
                    if (info.layout == .@"packed" or info.tag_type == null)
                        return;
                    const active_tag = std.meta.activeTag(ref.*);
                    const Tag = info.tag_type.?;
                    inline for (comptime std.meta.tags(Tag)) |tag| {
                        if (tag == active_tag) {
                            var payload_copy = @field(ref.*, @tagName(tag));
                            log.debug(F("fixup: {s}.{s}: {any}"), .{
                                @typeName(T),
                                @tagName(tag),
                                std.mem.asBytes(&payload_copy),
                            });
                            try self.fixup(std.meta.TagPayload(T, tag), &payload_copy, resolved);
                            ref.* = @unionInit(T, @tagName(tag), payload_copy);
                        }
                    }
                },
                .optional => |info| {
                    if (@typeInfo(info.child) != .optional)
                        @compileError("Nested optionals are not supported");
                    if (ref != null) {
                        var copy: info.child = ref.*.?;
                        try self.fixup(info.child, &copy, resolved);
                        ref.* = copy;
                    }
                },
                .pointer => |info| {
                    if (info.is_volatile)
                        return;

                    const slice: Slice(T) = switch (info.size) {
                        .c => @compileError("C pointers are not supported"),
                        .one => @as(Pointer(T), @ptrCast(ref.*))[0..1],
                        .many => z: {
                            _ = info.sentinel() orelse @compileError("Sentinel is required for [*]T pointers");
                            const len = std.mem.len(ref.*);
                            break :z ref.*[0..len + 1];
                        },
                        .slice => z: {
                            const len = ref.*.len + if (info.sentinel()) |_| 1 else 0;
                            break :z ref.*[0..len];
                        },
                    };

                    const resolved_ptr = try self.push(slice, resolved);
                    if (precompute)
                        return;

                    switch (info.size) {
                        .c => unreachable,
                        .one => {
                            ref.* = @ptrCast(resolved_ptr);
                        },
                        .many => {
                            ref.* = @ptrCast(resolved_ptr);
                        },
                        .slice => if (info.sentinel()) |_| {
                            // ref.* = resolved_ptr[0..value.len: z]
                            // won't work here because of the runtime check
                            const ptr_bytes = asBytes(&ref.*.ptr);
                            const resolved_bytes = asBytes(&resolved_ptr);
                            @memcpy(ptr_bytes, resolved_bytes);
                        } else {
                            ref.* = resolved_ptr[0..ref.*.len];
                        },
                    }
                },
                else => {},
            }
        }

        fn rfixup(self: Self, comptime T: type, ref: *T) void {
            const base_addr = @intFromPtr(self.data.ptr);
            switch (@typeInfo(T)) {
                .@"struct" => |info| {
                    if (info.layout == .@"packed")
                        return;

                    inline for (info.fields) |f| {
                        const fptr = &@field(ref.*, f.name);
                        log.debug("rfixup: {s}.{s}: {any}", .{
                            @typeName(T),
                            f.name,
                            std.mem.asBytes(fptr),
                        });
                        self.rfixup(f.type, fptr);
                    }
                },
                .@"union" => |info| {
                    if (info.layout == .@"packed" or info.tag_type == null)
                        return;
                    const active_tag = std.meta.activeTag(ref.*);
                    const Tag = info.tag_type.?;
                    inline for (comptime std.meta.tags(Tag)) |tag| {
                        if (tag == active_tag) {
                            var payload_copy = @field(ref.*, @tagName(tag));
                            log.debug("rfixup: {s}.{s}: {any}", .{
                                @typeName(T),
                                @tagName(tag),
                                std.mem.asBytes(&payload_copy),
                            });
                            self.rfixup(std.meta.TagPayload(T, tag), &payload_copy);
                            ref.* = @unionInit(T, @tagName(tag), payload_copy);
                        }
                    }
                },
                .optional => |info| {
                    if (@typeInfo(info.child) != .optional)
                        @compileError("Nested optionals are not supported");
                    if (ref.* != null) {
                        var copy: info.child = ref.*.?;
                        self.rfixup(info.child, &copy);
                        ref.* = copy;
                    }
                },
                .pointer => |info| {
                    if (info.is_volatile)
                        return;

                    const offset: usize = switch (info.size) {
                        .c => @compileError("C pointers are not supported"),
                        .one => @intFromPtr(ref.*),
                        .many => z: {
                            _ = info.sentinel() orelse @compileError("Sentinel is required for [*]T pointers");
                            break :z @intFromPtr(ref.*) ;
                        },
                        .slice => @intFromPtr(ref.*.ptr),
                    };

                    if (offset > base_addr + self.data.len)
                        return;

                    const ptr: Pointer(T) = @ptrFromInt(base_addr + offset);
                    const slice: Slice(T) = switch (info.size) {
                        .c => @compileError("C pointers are not supported"),
                        .one => z: {
                            ref.* = @ptrCast(ptr);
                            break :z ptr[0..1];
                        },
                        .many => z: {
                            ref.* = @ptrCast(ptr);
                            const len = std.mem.len(@as(T, @ptrCast(ptr)));
                            break :z ptr[0..len + 1];
                        },
                        .slice => z: {
                            if (info.sentinel()) |s| {
                                ref.* = ptr[0..ref.*.len : s];
                                break :z ptr[0..ref.*.len + 1];
                            } else {
                                ref.* = ptr[0..ref.*.len];
                                break :z ptr[0..ref.*.len];
                            }
                        },
                    };

                    for (slice) |*item| {
                        self.read(info.child, @constCast(item));
                    }
                },
                else => {},
            }
        }

    fn push(self: Self, slice: anytype, resolved: *Map) !@TypeOf(slice.ptr) {
            const info = @typeInfo(@TypeOf(slice)).pointer;
            const addr = @intFromPtr(slice.ptr);

            const resolved_offset = resolved.get(addr) orelse resolve: {
                const aligned_offset = std.mem.alignForward(usize, self.used.*, info.alignment);
                try resolved.put(addr, aligned_offset);
                self.used.* = aligned_offset + slice.len * @sizeOf(info.child);

                for (slice, 0..) |item, i| {
                    var push_i: Self = self;
                    push_i.offset = aligned_offset + i * @sizeOf(info.child);
                    try push_i.write(info.child, item, resolved);
                }
                break :resolve aligned_offset;
            };

            log.debug(F("push.resolved: {any} -> {any}"), .{
                addr,
                resolved_offset,
            });
            return @ptrFromInt(resolved_offset);
        }
    };
}

/// Seal a value of type `T` into a `Pod(T)` of a compact binary buffer.
/// The caller owns the returned data.
pub fn seal(comptime T: type, value: T, allocator: Allocator) ![]align(ALIGNMENT) u8 {
    var used: usize = @sizeOf(Pod(T));
    var resolved = Map.init(allocator);
    defer resolved.deinit();

    const pod = Pod(T){ .value = value };
    const data = precompute: {
        const ctx = Context(true){
            .data = {},
            .used = &used,
        };
        defer {
            resolved.clearRetainingCapacity();
            used = @sizeOf(Pod(T));
        }
        try ctx.write(Pod(T), pod, &resolved);
        log.debug("seal.precompute: {d}", .{used});
        const data = try allocator.allocWithOptions(u8, used, ALIGNMENT, null);
        break :precompute data;
    };

    const ctx = Context(false){
        .data = data,
        .used = &used,
    };
    // We've already allocated everything
    ctx.write(Pod(T), pod, &resolved) catch unreachable;
    return data;
}

/// Unseal a sealed `Pod(T)` data back into the original type `T`.
/// The caller owns the data and *must ensure* it is valid for
/// the lifetime of the returned value.
pub fn unseal(comptime T: type, data: []align(ALIGNMENT) u8) !T {
    const magic_baseline = comptime Magic.init(T);
    const magic: Magic = z: {
        const offset = @offsetOf(Pod(T), "magic");
        const ptr: *const Magic = @alignCast(@ptrCast(&data[offset]));
        const native_value = ptr.*;
        if (native_value.hash == magic_baseline.hash and native_value.little_endian == magic_baseline.little_endian) {
            @branchHint(.likely);
            break :z native_value;
        }

        const backing: u128 = @bitCast(native_value);
        const bs_value: Magic = @bitCast(@byteSwap(backing));
        if (bs_value.hash == magic_baseline.hash and bs_value.little_endian != magic_baseline.little_endian)
            break :z bs_value;

        return error.MagicMismatch;
    };

    if (magic.version != VERSION)
        return error.VersionMismatch;

    if (magic.little_endian != magic_baseline.little_endian) {
        @branchHint(.unlikely);
        for (data) |*byte| {
            byte.* = @byteSwap(byte.*);
        }
    }

    const ref: *Pod(T) = @ptrCast(data.ptr);
    const ctx = Context(false){
        .used = undefined,
        .data = data,
    };
    ctx.read(Pod(T), ref);
    return ref.value;
}

const T0 = struct {
    const S0 = struct {
        a: u8 = 31,
        b: u8 = 32,
        c: *u8,
    };

    const bytes: []const u8 = &.{ 11, 12, 21, 22, 23, 0 };
    number: u32 = 42,
    u8_slice: []const u8 = bytes[0..2],
    u8_slicez: [:0]const u8 = bytes[2..5:0],
    u8_ptrz: [*:0]const u8 = bytes[2..5:0].ptr,
    s0p: *const S0,
};

const T1 = union(enum) {
    number: u32,
    u8_slice: []const u8,

    pub const POD_MAGIC = 0x1234567890abcde;
};

test {
    const allocator = std.testing.allocator;
    std.testing.log_level = .debug;

    {
        var c: u8 = 119;
        var s0 = T0.S0{ .c = &c };
        const t0 = T0{ .s0p = &s0 };
        const t0_data = try seal(T0, t0, allocator);
        defer allocator.free(t0_data);
        const _t0 = try unseal(T0, t0_data);

        try std.testing.expectEqual(_t0.number, t0.number);
        try std.testing.expectEqualStrings(_t0.u8_slice, t0.u8_slice);
        try std.testing.expectEqualStrings(_t0.u8_slicez, t0.u8_slicez);
        try std.testing.expectEqualStrings(std.mem.span(_t0.u8_ptrz), std.mem.span(t0.u8_ptrz));
        try std.testing.expectEqual(_t0.s0p.*.a, s0.a);
        try std.testing.expectEqual(_t0.s0p.*.b, s0.b);
        try std.testing.expectEqual(_t0.s0p.*.c.*, s0.c.*);
    }

    {
        const t1 = T1{ .u8_slice = &.{ 45, 46, 47, 48 } };
        const t1_data = try seal(T1, t1, allocator);
        defer allocator.free(t1_data);
        const _t1 = try unseal(T1, t1_data);

        try std.testing.expect(_t1 == .u8_slice);
        try std.testing.expectEqualStrings(_t1.u8_slice, t1.u8_slice);
    }
}

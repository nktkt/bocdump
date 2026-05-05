const std = @import("std");

const Allocator = std.mem.Allocator;
const version = "0.2.0";
const max_input_bytes = 64 * 1024 * 1024;

const OutputMode = enum {
    text,
    json,
};

const InputKind = enum {
    file,
    hex,
    base64,
};

const DecodeKind = enum {
    message,

    fn label(self: DecodeKind) []const u8 {
        return switch (self) {
            .message => "message",
        };
    }
};

const CliOptions = struct {
    output: OutputMode = .text,
    input_kind: ?InputKind = null,
    input_value: ?[]const u8 = null,
    decode: ?DecodeKind = null,
};

const Magic = enum {
    generic,
    legacy_indexed,
    legacy_indexed_crc32c,

    fn label(self: Magic) []const u8 {
        return switch (self) {
            .generic => "generic b5ee9c72",
            .legacy_indexed => "legacy indexed 68ff65f3",
            .legacy_indexed_crc32c => "legacy indexed+crc32c acc3a728",
        };
    }
};

const CellKind = enum {
    ordinary,
    pruned_branch,
    library_reference,
    merkle_proof,
    merkle_update,
    unknown_exotic,

    fn label(self: CellKind) []const u8 {
        return switch (self) {
            .ordinary => "ordinary",
            .pruned_branch => "pruned_branch",
            .library_reference => "library_reference",
            .merkle_proof => "merkle_proof",
            .merkle_update => "merkle_update",
            .unknown_exotic => "unknown_exotic",
        };
    }
};

const Cell = struct {
    index: usize,
    start_offset: usize,
    end_offset: usize,
    d1: u8,
    d2: u8,
    refs_count: usize,
    exotic: bool,
    has_hashes: bool,
    level_mask: u8,
    hashes_count: usize,
    hashes: []const u8,
    depths: []const u8,
    padding_added: bool,
    data_bytes: []const u8,
    data_bits: usize,
    refs: []usize,
    kind: CellKind,
    computed_hashes: [4][32]u8,
    computed_depths: [4]u16,
    computed: bool,

    fn deinit(self: *Cell, allocator: Allocator) void {
        if (self.refs.len > 0) allocator.free(self.refs);
    }
};

const Boc = struct {
    allocator: Allocator,
    magic_value: u32,
    magic: Magic,
    has_idx: bool,
    has_crc32c: bool,
    has_cache_bits: bool,
    flags: u8,
    size_bytes: usize,
    off_bytes: usize,
    cells_count: usize,
    roots_count: usize,
    absent_count: usize,
    total_cell_size: usize,
    roots: []usize,
    index: []usize,
    cell_data: []const u8,
    crc32c_expected: ?u32,
    crc32c_actual: ?u32,
    cells: []Cell,
    index_matches_cells: ?bool,
    topology_ok: bool,

    fn deinit(self: *Boc) void {
        if (self.roots.len > 0) self.allocator.free(self.roots);
        if (self.index.len > 0) self.allocator.free(self.index);
        for (self.cells) |*cell| {
            cell.deinit(self.allocator);
        }
        if (self.cells.len > 0) self.allocator.free(self.cells);
    }
};

const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn remaining(self: Reader) usize {
        return self.bytes.len - self.pos;
    }

    fn readByte(self: *Reader) !u8 {
        if (self.remaining() < 1) return error.ShortInput;
        const value = self.bytes[self.pos];
        self.pos += 1;
        return value;
    }

    fn readBytes(self: *Reader, len: usize) ![]const u8 {
        if (self.remaining() < len) return error.ShortInput;
        const start = self.pos;
        self.pos += len;
        return self.bytes[start..self.pos];
    }

    fn readUInt(self: *Reader, len: usize) !usize {
        if (len == 0 or len > 8) return error.InvalidIntegerWidth;
        const raw = try self.readBytes(len);
        var value: u64 = 0;
        for (raw) |byte| {
            value = (value << 8) | byte;
        }
        if (value > std.math.maxInt(usize)) return error.IntegerOverflow;
        return @as(usize, @intCast(value));
    }
};

pub fn main() void {
    run() catch |err| {
        std.debug.print("error: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn run() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var stdout_buffer: [8192]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;
    defer stdout.flush() catch {};

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len == 1 or std.mem.eql(u8, args[1], "--help") or std.mem.eql(u8, args[1], "-h")) {
        try printUsage(stdout);
        return;
    }
    if (args.len == 2 and (std.mem.eql(u8, args[1], "--version") or std.mem.eql(u8, args[1], "-V"))) {
        try stdout.print("bocdump {s}\n", .{version});
        return;
    }

    const options = try parseArgs(args);
    if (options.decode != null and options.output != .json) return error.DecodeRequiresJson;

    const input = try loadInput(allocator, options);
    defer allocator.free(input);

    var boc = try parseBoc(allocator, input);
    defer boc.deinit();

    switch (options.output) {
        .text => try dumpBoc(stdout, &boc),
        .json => try dumpBocJson(stdout, &boc, options.decode),
    }
}

fn printUsage(writer: anytype) !void {
    try writer.writeAll(
        \\Usage:
        \\  bocdump --version
        \\  bocdump [--json] --hex <hex>
        \\  bocdump [--json] --base64 <base64>
        \\  bocdump [--json] --file <path>
        \\  bocdump [--json] <path>
        \\  bocdump [--json] --file -
        \\  bocdump --json --decode message --hex <hex>
        \\
        \\Dumps and validates TON Bag-of-Cells headers, cell records, hashes, and depths.
        \\Use --decode message to parse the root cell as a TON Message and append JSON decode output.
        \\
    );
}

fn parseArgs(args: []const [:0]const u8) !CliOptions {
    var options = CliOptions{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--json")) {
            options.output = .json;
            continue;
        }
        if (std.mem.eql(u8, arg, "--text")) {
            options.output = .text;
            continue;
        }
        if (std.mem.eql(u8, arg, "--decode")) {
            if (options.decode != null) return error.InvalidArguments;
            if (i + 1 >= args.len) return error.InvalidArguments;
            i += 1;
            options.decode = try parseDecodeKind(args[i]);
            continue;
        }
        if (std.mem.eql(u8, arg, "--hex") or std.mem.eql(u8, arg, "--base64") or std.mem.eql(u8, arg, "--file")) {
            if (options.input_kind != null) return error.InvalidArguments;
            if (i + 1 >= args.len) return error.InvalidArguments;
            options.input_kind = if (std.mem.eql(u8, arg, "--hex"))
                .hex
            else if (std.mem.eql(u8, arg, "--base64"))
                .base64
            else
                .file;
            i += 1;
            options.input_value = args[i];
            continue;
        }
        if (std.mem.startsWith(u8, arg, "-")) return error.InvalidArguments;
        if (options.input_kind != null) return error.InvalidArguments;
        options.input_kind = .file;
        options.input_value = arg;
    }
    if (options.input_kind == null or options.input_value == null) return error.InvalidArguments;
    return options;
}

fn parseDecodeKind(value: []const u8) !DecodeKind {
    if (std.mem.eql(u8, value, "message")) return .message;
    return error.InvalidArguments;
}

fn loadInput(allocator: Allocator, options: CliOptions) ![]u8 {
    const input_value = options.input_value orelse return error.InvalidArguments;
    return switch (options.input_kind orelse return error.InvalidArguments) {
        .hex => decodeHexAlloc(allocator, input_value),
        .base64 => decodeBase64Alloc(allocator, input_value),
        .file => readPathOrStdin(allocator, input_value),
    };
}

fn readPathOrStdin(allocator: Allocator, path: []const u8) ![]u8 {
    if (std.mem.eql(u8, path, "-")) {
        return std.fs.File.stdin().readToEndAlloc(allocator, max_input_bytes);
    }
    return std.fs.cwd().readFileAlloc(allocator, path, max_input_bytes);
}

fn decodeHexAlloc(allocator: Allocator, input: []const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, input, " \t\r\n");
    const no_prefix = if (std.mem.startsWith(u8, trimmed, "0x") or std.mem.startsWith(u8, trimmed, "0X"))
        trimmed[2..]
    else
        trimmed;

    var clean: std.ArrayList(u8) = .empty;
    defer clean.deinit(allocator);
    for (no_prefix) |byte| {
        if (std.ascii.isWhitespace(byte) or byte == '_') continue;
        try clean.append(allocator, byte);
    }

    const clean_slice = try clean.toOwnedSlice(allocator);
    defer allocator.free(clean_slice);

    const out = try allocator.alloc(u8, clean_slice.len / 2);
    errdefer allocator.free(out);
    _ = try std.fmt.hexToBytes(out, clean_slice);
    return out;
}

fn decodeBase64Alloc(allocator: Allocator, input: []const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, input, " \t\r\n");
    const out_len = try std.base64.standard.Decoder.calcSizeForSlice(trimmed);
    const out = try allocator.alloc(u8, out_len);
    errdefer allocator.free(out);
    try std.base64.standard.Decoder.decode(out, trimmed);
    return out;
}

fn parseBoc(allocator: Allocator, bytes: []const u8) !Boc {
    var reader = Reader{ .bytes = bytes };
    const magic_value = try reader.readUInt(4);

    var boc = Boc{
        .allocator = allocator,
        .magic_value = @as(u32, @intCast(magic_value)),
        .magic = undefined,
        .has_idx = false,
        .has_crc32c = false,
        .has_cache_bits = false,
        .flags = 0,
        .size_bytes = 0,
        .off_bytes = 0,
        .cells_count = 0,
        .roots_count = 0,
        .absent_count = 0,
        .total_cell_size = 0,
        .roots = &.{},
        .index = &.{},
        .cell_data = &.{},
        .crc32c_expected = null,
        .crc32c_actual = null,
        .cells = &.{},
        .index_matches_cells = null,
        .topology_ok = true,
    };
    errdefer boc.deinit();

    switch (magic_value) {
        0xb5ee9c72 => try parseGenericHeader(&reader, &boc),
        0x68ff65f3 => try parseLegacyHeader(&reader, &boc, .legacy_indexed),
        0xacc3a728 => try parseLegacyHeader(&reader, &boc, .legacy_indexed_crc32c),
        else => return error.InvalidMagic,
    }

    if (boc.size_bytes == 0 or boc.size_bytes > 4) return error.InvalidHeader;
    if (boc.off_bytes == 0 or boc.off_bytes > 8) return error.InvalidHeader;
    if (boc.roots_count == 0) return error.InvalidHeader;
    if (boc.roots_count + boc.absent_count > boc.cells_count) return error.InvalidHeader;
    if (boc.flags != 0) return error.UnsupportedFlags;

    boc.cells = try parseCells(allocator, boc.cell_data, boc.cells_count, boc.size_bytes);

    if (boc.index.len > 0) {
        var ok = boc.index.len == boc.cells.len;
        if (ok) {
            for (boc.cells, 0..) |cell, i| {
                if (boc.index[i] != cell.end_offset) {
                    ok = false;
                    break;
                }
            }
        }
        boc.index_matches_cells = ok;
    }

    for (boc.roots) |root| {
        if (root >= boc.cells_count) return error.RootOutOfRange;
    }

    var topology_ok = true;
    for (boc.cells, 0..) |cell, i| {
        for (cell.refs) |ref| {
            if (ref >= boc.cells_count) return error.RefOutOfRange;
            if (ref <= i) topology_ok = false;
        }
    }
    boc.topology_ok = topology_ok;
    if (!boc.topology_ok) return error.InvalidTopologicalOrder;

    try computeCellMetadata(&boc);

    return boc;
}

fn parseGenericHeader(reader: *Reader, boc: *Boc) !void {
    boc.magic = .generic;

    const flags_byte = try reader.readByte();
    boc.has_idx = (flags_byte & 0x80) != 0;
    boc.has_crc32c = (flags_byte & 0x40) != 0;
    boc.has_cache_bits = (flags_byte & 0x20) != 0;
    boc.flags = @as(u8, @intCast((flags_byte >> 3) & 0x03));
    boc.size_bytes = flags_byte & 0x07;
    boc.off_bytes = try reader.readByte();

    boc.cells_count = try reader.readUInt(boc.size_bytes);
    boc.roots_count = try reader.readUInt(boc.size_bytes);
    boc.absent_count = try reader.readUInt(boc.size_bytes);
    boc.total_cell_size = try reader.readUInt(boc.off_bytes);

    boc.roots = try boc.allocator.alloc(usize, boc.roots_count);
    for (boc.roots) |*root| {
        root.* = try reader.readUInt(boc.size_bytes);
    }

    if (boc.has_idx) {
        boc.index = try boc.allocator.alloc(usize, boc.cells_count);
        for (boc.index) |*entry| {
            entry.* = try reader.readUInt(boc.off_bytes);
        }
    }

    boc.cell_data = try reader.readBytes(boc.total_cell_size);

    if (boc.has_crc32c) {
        const crc_bytes = try reader.readBytes(4);
        boc.crc32c_expected = std.mem.readInt(u32, crc_bytes[0..4], .little);
        boc.crc32c_actual = std.hash.crc.Crc32Iscsi.hash(reader.bytes[0 .. reader.bytes.len - 4]);
        if (boc.crc32c_expected.? != boc.crc32c_actual.?) return error.InvalidCrc32c;
    }

    if (reader.remaining() != 0) return error.TrailingBytes;
}

fn parseLegacyHeader(reader: *Reader, boc: *Boc, magic: Magic) !void {
    boc.magic = magic;
    boc.has_idx = true;
    boc.has_crc32c = magic == .legacy_indexed_crc32c;

    boc.size_bytes = try reader.readByte();
    boc.off_bytes = try reader.readByte();
    boc.cells_count = try reader.readUInt(boc.size_bytes);
    boc.roots_count = try reader.readUInt(boc.size_bytes);
    boc.absent_count = try reader.readUInt(boc.size_bytes);
    boc.total_cell_size = try reader.readUInt(boc.off_bytes);

    if (boc.roots_count != 1) return error.InvalidHeader;
    boc.roots = try boc.allocator.alloc(usize, 1);
    boc.roots[0] = 0;

    boc.index = try boc.allocator.alloc(usize, boc.cells_count);
    for (boc.index) |*entry| {
        entry.* = try reader.readUInt(boc.off_bytes);
    }

    boc.cell_data = try reader.readBytes(boc.total_cell_size);

    if (boc.has_crc32c) {
        const crc_bytes = try reader.readBytes(4);
        boc.crc32c_expected = std.mem.readInt(u32, crc_bytes[0..4], .little);
        boc.crc32c_actual = std.hash.crc.Crc32Iscsi.hash(reader.bytes[0 .. reader.bytes.len - 4]);
        if (boc.crc32c_expected.? != boc.crc32c_actual.?) return error.InvalidCrc32c;
    }

    if (reader.remaining() != 0) return error.TrailingBytes;
}

fn parseCells(allocator: Allocator, cell_data: []const u8, cells_count: usize, size_bytes: usize) ![]Cell {
    var reader = Reader{ .bytes = cell_data };
    const cells = try allocator.alloc(Cell, cells_count);
    errdefer allocator.free(cells);

    var initialized: usize = 0;
    errdefer {
        for (cells[0..initialized]) |*cell| {
            cell.deinit(allocator);
        }
    }

    for (cells, 0..) |*cell, i| {
        const start = reader.pos;
        const d1 = try reader.readByte();
        const d2 = try reader.readByte();
        const refs_count = @as(usize, d1 & 0x07);
        if (refs_count > 4) return error.TooManyRefs;
        const level_mask = @as(u8, @intCast(d1 >> 5));
        const has_hashes = (d1 & 0x10) != 0;
        const hashes_count = if (has_hashes) getHashesCount(level_mask) else 0;
        const hashes = try reader.readBytes(hashes_count * 32);
        const depths = try reader.readBytes(hashes_count * 2);
        const data_bytes_len = (@as(usize, d2) + 1) / 2;
        const padding_added = (d2 & 1) != 0;
        const data_bytes = try reader.readBytes(data_bytes_len);
        const data_bits = if (padding_added)
            try paddedBitLength(data_bytes)
        else
            data_bytes_len * 8;
        if (data_bits > 1023) return error.CellDataTooLarge;
        if (bitsDescriptor(data_bits) != d2) return error.InvalidBitsDescriptor;

        const refs = try allocator.alloc(usize, refs_count);
        errdefer allocator.free(refs);
        for (refs) |*ref| {
            ref.* = try reader.readUInt(size_bytes);
        }

        cell.* = .{
            .index = i,
            .start_offset = start,
            .end_offset = reader.pos,
            .d1 = d1,
            .d2 = d2,
            .refs_count = refs_count,
            .exotic = (d1 & 0x08) != 0,
            .has_hashes = has_hashes,
            .level_mask = level_mask,
            .hashes_count = hashes_count,
            .hashes = hashes,
            .depths = depths,
            .padding_added = padding_added,
            .data_bytes = data_bytes,
            .data_bits = data_bits,
            .refs = refs,
            .kind = if ((d1 & 0x08) != 0) .unknown_exotic else .ordinary,
            .computed_hashes = [_][32]u8{[_]u8{0} ** 32} ** 4,
            .computed_depths = [_]u16{0} ** 4,
            .computed = false,
        };
        initialized += 1;
    }

    if (reader.remaining() != 0) return error.TrailingCellData;
    return cells;
}

fn computeCellMetadata(boc: *Boc) !void {
    var i = boc.cells.len;
    while (i > 0) {
        i -= 1;
        if (boc.cells[i].exotic) {
            try computeExoticCell(boc.cells, i);
        } else {
            try computeOrdinaryCell(boc.cells, i);
        }
    }
}

fn computeOrdinaryCell(cells: []Cell, index: usize) !void {
    var expected_mask: u8 = 0;
    for (cells[index].refs) |ref| {
        expected_mask |= cells[ref].level_mask;
    }
    if (cells[index].level_mask != expected_mask) return error.InvalidLevelMask;
    try computeNonPrunedHashes(cells, index, .ordinary, cells[index].level_mask, 0);
}

fn computeExoticCell(cells: []Cell, index: usize) !void {
    const kind = try resolveExoticKind(&cells[index]);
    cells[index].kind = kind;
    switch (kind) {
        .ordinary => unreachable,
        .unknown_exotic => return error.UnsupportedExoticCell,
        .library_reference => {
            if (cells[index].data_bits != 264) return error.InvalidExoticCell;
            if (cells[index].refs.len != 0) return error.InvalidExoticCell;
            if (cells[index].level_mask != 0) return error.InvalidLevelMask;
            try computeNonPrunedHashes(cells, index, kind, 0, 0);
        },
        .merkle_proof => {
            if (cells[index].data_bits != 280 or cells[index].refs.len != 1) return error.InvalidExoticCell;
            const ref = cells[index].refs[0];
            if (!std.mem.eql(u8, cells[index].data_bytes[1..33], &cells[ref].computed_hashes[0])) return error.InvalidExoticCell;
            const depth = std.mem.readInt(u16, cells[index].data_bytes[33..][0..2], .big);
            if (depth != cells[ref].computed_depths[0]) return error.InvalidExoticCell;
            const mask = cells[ref].level_mask >> 1;
            if (cells[index].level_mask != mask) return error.InvalidLevelMask;
            try computeNonPrunedHashes(cells, index, kind, mask, 1);
        },
        .merkle_update => {
            if (cells[index].data_bits != 552 or cells[index].refs.len != 2) return error.InvalidExoticCell;
            const ref0 = cells[index].refs[0];
            const ref1 = cells[index].refs[1];
            if (!std.mem.eql(u8, cells[index].data_bytes[1..33], &cells[ref0].computed_hashes[0])) return error.InvalidExoticCell;
            if (!std.mem.eql(u8, cells[index].data_bytes[33..65], &cells[ref1].computed_hashes[0])) return error.InvalidExoticCell;
            const depth0 = std.mem.readInt(u16, cells[index].data_bytes[65..][0..2], .big);
            const depth1 = std.mem.readInt(u16, cells[index].data_bytes[67..][0..2], .big);
            if (depth0 != cells[ref0].computed_depths[0]) return error.InvalidExoticCell;
            if (depth1 != cells[ref1].computed_depths[0]) return error.InvalidExoticCell;
            const mask = (cells[ref0].level_mask | cells[ref1].level_mask) >> 1;
            if (cells[index].level_mask != mask) return error.InvalidLevelMask;
            try computeNonPrunedHashes(cells, index, kind, mask, 1);
        },
        .pruned_branch => try computePrunedBranch(cells, index),
    }
}

fn resolveExoticKind(cell: *const Cell) !CellKind {
    if (cell.data_bits < 8 or cell.data_bytes.len == 0) return error.InvalidExoticCell;
    return switch (cell.data_bytes[0]) {
        1 => .pruned_branch,
        2 => .library_reference,
        3 => .merkle_proof,
        4 => .merkle_update,
        else => .unknown_exotic,
    };
}

fn computeNonPrunedHashes(cells: []Cell, index: usize, kind: CellKind, mask: u8, ref_level_offset: usize) !void {
    var compact_hashes = [_][32]u8{[_]u8{0} ** 32} ** 4;
    var compact_depths = [_]u16{0} ** 4;
    var compact_index: usize = 0;
    const max_level = levelMaskLevel(mask);

    var level: usize = 0;
    while (level <= max_level) : (level += 1) {
        if (!isSignificantLevel(mask, level)) continue;

        const current_bits = if (compact_index == 0)
            cells[index].data_bytes
        else
            compact_hashes[compact_index - 1][0..];

        compact_depths[compact_index] = try computeDepth(cells, index, level, ref_level_offset);
        compact_hashes[compact_index] = computeReprHash(cells, index, kind, level, current_bits, ref_level_offset);
        compact_index += 1;
    }

    fillResolvedHashes(mask, compact_hashes, compact_depths, &cells[index]);
    cells[index].level_mask = mask;
    cells[index].kind = kind;
    cells[index].computed = true;
}

fn computePrunedBranch(cells: []Cell, index: usize) !void {
    if (cells[index].refs.len != 0) return error.InvalidExoticCell;
    if (cells[index].data_bits != 280 and cells[index].data_bits < 288) return error.InvalidExoticCell;

    var mask: u8 = 1;
    var cursor: usize = 1;
    if (cells[index].data_bits != 280) {
        mask = cells[index].data_bytes[cursor];
        cursor += 1;
        const level = levelMaskLevel(mask);
        if (level < 1 or level > 3) return error.InvalidExoticCell;
        const expected_bits = 16 + level * (256 + 16);
        if (cells[index].data_bits != expected_bits) return error.InvalidExoticCell;
    }
    if (cells[index].level_mask != mask) return error.InvalidLevelMask;

    const entries = levelMaskLevel(mask);
    var pruned_hashes = [_][32]u8{[_]u8{0} ** 32} ** 4;
    var pruned_depths = [_]u16{0} ** 4;
    var i: usize = 0;
    while (i < entries) : (i += 1) {
        @memcpy(&pruned_hashes[i], cells[index].data_bytes[cursor .. cursor + 32]);
        cursor += 32;
    }
    i = 0;
    while (i < entries) : (i += 1) {
        pruned_depths[i] = std.mem.readInt(u16, cells[index].data_bytes[cursor..][0..2], .big);
        cursor += 2;
    }

    const this_hash_index = hashIndex(mask);
    const computed_depth: u16 = 0;
    const computed_hash = computeReprHash(cells, index, .pruned_branch, levelMaskLevel(mask), cells[index].data_bytes, 0);

    var level: usize = 0;
    while (level < 4) : (level += 1) {
        const idx = hashIndex(levelMaskApply(mask, level));
        if (idx == this_hash_index) {
            cells[index].computed_hashes[level] = computed_hash;
            cells[index].computed_depths[level] = computed_depth;
        } else {
            if (idx >= entries) return error.InvalidExoticCell;
            cells[index].computed_hashes[level] = pruned_hashes[idx];
            cells[index].computed_depths[level] = pruned_depths[idx];
        }
    }
    cells[index].kind = .pruned_branch;
    cells[index].computed = true;
}

fn computeDepth(cells: []const Cell, index: usize, level: usize, ref_level_offset: usize) !u16 {
    var depth: usize = 0;
    for (cells[index].refs) |ref| {
        const child_level = @min(level + ref_level_offset, 3);
        depth = @max(depth, cells[ref].computed_depths[child_level]);
    }
    if (cells[index].refs.len > 0) depth += 1;
    if (depth > std.math.maxInt(u16)) return error.CellDepthOverflow;
    return @as(u16, @intCast(depth));
}

fn computeReprHash(cells: []const Cell, index: usize, kind: CellKind, level: usize, current_bits: []const u8, ref_level_offset: usize) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    const applied_mask = levelMaskApply(cells[index].level_mask, level);
    const descriptor = [_]u8{
        refsDescriptor(cells[index].refs.len, kind != .ordinary, applied_mask),
        cells[index].d2,
    };
    hasher.update(&descriptor);
    hasher.update(current_bits);
    for (cells[index].refs) |ref| {
        const child_level = @min(level + ref_level_offset, 3);
        var depth_bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &depth_bytes, cells[ref].computed_depths[child_level], .big);
        hasher.update(&depth_bytes);
    }
    for (cells[index].refs) |ref| {
        const child_level = @min(level + ref_level_offset, 3);
        hasher.update(&cells[ref].computed_hashes[child_level]);
    }
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

fn fillResolvedHashes(mask: u8, compact_hashes: [4][32]u8, compact_depths: [4]u16, cell: *Cell) void {
    var level: usize = 0;
    while (level < 4) : (level += 1) {
        const idx = hashIndex(levelMaskApply(mask, level));
        cell.computed_hashes[level] = compact_hashes[idx];
        cell.computed_depths[level] = compact_depths[idx];
    }
}

fn getHashesCount(level_mask: u8) usize {
    var mask = level_mask & 0x07;
    var count: usize = 1;
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        count += mask & 1;
        mask >>= 1;
    }
    return count;
}

fn refsDescriptor(refs_count: usize, exotic: bool, level_mask: u8) u8 {
    return @as(u8, @intCast(refs_count + (if (exotic) @as(usize, 8) else 0) + @as(usize, level_mask) * 32));
}

fn bitsDescriptor(bit_len: usize) u8 {
    return @as(u8, @intCast((bit_len / 8) + ((bit_len + 7) / 8)));
}

fn levelMaskApply(mask: u8, level: usize) u8 {
    const limit = (@as(u16, 1) << @as(u4, @intCast(level))) - 1;
    return mask & @as(u8, @intCast(limit));
}

fn hashIndex(mask: u8) usize {
    return @popCount(mask & 0x07);
}

fn levelMaskLevel(mask: u8) usize {
    if ((mask & 0b100) != 0) return 3;
    if ((mask & 0b010) != 0) return 2;
    if ((mask & 0b001) != 0) return 1;
    return 0;
}

fn isSignificantLevel(mask: u8, level: usize) bool {
    if (level == 0) return true;
    return ((mask >> @as(u3, @intCast(level - 1))) & 1) != 0;
}

fn paddedBitLength(data: []const u8) !usize {
    if (data.len == 0) return error.InvalidPadding;
    const last = data[data.len - 1];
    if (last == 0) return error.InvalidPadding;

    var trailing_zero_bits: usize = 0;
    var mask: u8 = 1;
    while ((last & mask) == 0) : (mask <<= 1) {
        trailing_zero_bits += 1;
        if (trailing_zero_bits == 8) return error.InvalidPadding;
    }
    return data.len * 8 - trailing_zero_bits - 1;
}

const Anycast = struct {
    depth: usize,
    prefix: [4]u8,
};

const InternalAddress = struct {
    workchain: i16,
    hash: [32]u8,
    anycast: ?Anycast,
};

const ExternalAddress = struct {
    bits: usize,
    value: [64]u8,
};

const DecodedAddress = union(enum) {
    none,
    internal: InternalAddress,
    external: ExternalAddress,
};

const AddressExpectation = enum {
    internal,
    maybe_external,
};

const ExtraCurrencyCollection = union(enum) {
    empty,
    dict_ref: usize,
};

const CurrencyCollection = struct {
    coins: u128,
    extra_currencies: ExtraCurrencyCollection,
};

const MessageInfo = union(enum) {
    internal: InternalMessageInfo,
    external_in: ExternalInMessageInfo,
    external_out: ExternalOutMessageInfo,
};

const InternalMessageInfo = struct {
    ihr_disabled: bool,
    bounce: bool,
    bounced: bool,
    src: DecodedAddress,
    dest: DecodedAddress,
    value: CurrencyCollection,
    ihr_fee: u128,
    forward_fee: u128,
    created_lt: u128,
    created_at: u64,
};

const ExternalInMessageInfo = struct {
    src: DecodedAddress,
    dest: DecodedAddress,
    import_fee: u128,
};

const ExternalOutMessageInfo = struct {
    src: DecodedAddress,
    dest: DecodedAddress,
    created_lt: u128,
    created_at: u64,
};

const SliceSummary = struct {
    bits: usize,
    refs: usize,
};

const StateInitLocation = union(enum) {
    none,
    ref: usize,
};

const BodyLocation = union(enum) {
    in_place: SliceSummary,
    ref: usize,
};

const DecodedMessage = struct {
    root: usize,
    info: MessageInfo,
    init: StateInitLocation,
    body: BodyLocation,
};

const CellSlice = struct {
    boc: *const Boc,
    cell_index: usize,
    bit_pos: usize = 0,
    ref_pos: usize = 0,

    fn cell(self: *const CellSlice) *const Cell {
        return &self.boc.cells[self.cell_index];
    }

    fn remainingBits(self: *const CellSlice) usize {
        return self.cell().data_bits - self.bit_pos;
    }

    fn remainingRefs(self: *const CellSlice) usize {
        return self.cell().refs.len - self.ref_pos;
    }

    fn readBit(self: *CellSlice) !bool {
        if (self.bit_pos >= self.cell().data_bits) return error.DecodeShortCellBits;
        const byte = self.cell().data_bytes[self.bit_pos / 8];
        const shift = @as(u3, @intCast(7 - (self.bit_pos % 8)));
        const bit = ((byte >> shift) & 1) == 1;
        self.bit_pos += 1;
        return bit;
    }

    fn readUInt(self: *CellSlice, bits: usize) !u128 {
        if (bits > 128) return error.DecodeIntegerTooWide;
        var value: u128 = 0;
        var i: usize = 0;
        while (i < bits) : (i += 1) {
            value = (value << 1) | @intFromBool(try self.readBit());
        }
        return value;
    }

    fn readInt8(self: *CellSlice) !i16 {
        const raw = @as(u8, @intCast(try self.readUInt(8)));
        return if (raw < 128) @as(i16, raw) else @as(i16, raw) - 256;
    }

    fn readBitsToBytes(self: *CellSlice, out: []u8, bits: usize) !void {
        if (bits > out.len * 8) return error.DecodeBufferTooSmall;
        @memset(out, 0);
        var i: usize = 0;
        while (i < bits) : (i += 1) {
            if (try self.readBit()) {
                const shift = @as(u3, @intCast(7 - (i % 8)));
                out[i / 8] |= @as(u8, 1) << shift;
            }
        }
    }

    fn readRef(self: *CellSlice) !usize {
        if (self.ref_pos >= self.cell().refs.len) return error.DecodeShortCellRefs;
        const ref = self.cell().refs[self.ref_pos];
        self.ref_pos += 1;
        return ref;
    }

    fn consumeRemaining(self: *CellSlice) SliceSummary {
        const summary = SliceSummary{
            .bits = self.remainingBits(),
            .refs = self.remainingRefs(),
        };
        self.bit_pos = self.cell().data_bits;
        self.ref_pos = self.cell().refs.len;
        return summary;
    }
};

fn decodeMessage(boc: *const Boc) !DecodedMessage {
    if (boc.roots.len != 1) return error.DecodeExpectedSingleRoot;
    const root = boc.roots[0];
    if (boc.cells[root].exotic) return error.DecodeRootExotic;

    var slice = CellSlice{ .boc = boc, .cell_index = root };
    const info = try decodeCommonMessageInfo(&slice);

    const init = try decodeStateInitLocation(&slice);
    const body = try decodeBodyLocation(&slice);
    if (slice.remainingBits() != 0 or slice.remainingRefs() != 0) return error.DecodeTrailingData;

    return .{
        .root = root,
        .info = info,
        .init = init,
        .body = body,
    };
}

fn decodeCommonMessageInfo(slice: *CellSlice) !MessageInfo {
    if (!try slice.readBit()) {
        return .{ .internal = .{
            .ihr_disabled = try slice.readBit(),
            .bounce = try slice.readBit(),
            .bounced = try slice.readBit(),
            .src = try decodeAddress(slice, .internal),
            .dest = try decodeAddress(slice, .internal),
            .value = try decodeCurrencyCollection(slice),
            .ihr_fee = try decodeCoins(slice),
            .forward_fee = try decodeCoins(slice),
            .created_lt = try slice.readUInt(64),
            .created_at = @as(u64, @intCast(try slice.readUInt(32))),
        } };
    }

    if (!try slice.readBit()) {
        return .{ .external_in = .{
            .src = try decodeAddress(slice, .maybe_external),
            .dest = try decodeAddress(slice, .internal),
            .import_fee = try decodeCoins(slice),
        } };
    }

    return .{ .external_out = .{
        .src = try decodeAddress(slice, .internal),
        .dest = try decodeAddress(slice, .maybe_external),
        .created_lt = try slice.readUInt(64),
        .created_at = @as(u64, @intCast(try slice.readUInt(32))),
    } };
}

fn decodeStateInitLocation(slice: *CellSlice) !StateInitLocation {
    if (!try slice.readBit()) return .none;
    if (try slice.readBit()) return .{ .ref = try slice.readRef() };
    return error.DecodeInlineStateInitUnsupported;
}

fn decodeBodyLocation(slice: *CellSlice) !BodyLocation {
    if (try slice.readBit()) {
        return .{ .ref = try slice.readRef() };
    }
    return .{ .in_place = slice.consumeRemaining() };
}

fn decodeAddress(slice: *CellSlice, expectation: AddressExpectation) !DecodedAddress {
    const tag = try slice.readUInt(2);
    switch (tag) {
        0 => {
            if (expectation == .internal) return error.DecodeInvalidAddress;
            return .none;
        },
        1 => {
            if (expectation == .internal) return error.DecodeInvalidAddress;
            return .{ .external = try decodeExternalAddress(slice) };
        },
        2 => return .{ .internal = try decodeInternalAddress(slice) },
        3 => return error.DecodeUnsupportedVariableAddress,
        else => unreachable,
    }
}

fn decodeInternalAddress(slice: *CellSlice) !InternalAddress {
    const anycast = try decodeMaybeAnycast(slice);
    const workchain = try slice.readInt8();
    var hash: [32]u8 = undefined;
    try slice.readBitsToBytes(&hash, 256);
    return .{
        .workchain = workchain,
        .hash = hash,
        .anycast = anycast,
    };
}

fn decodeExternalAddress(slice: *CellSlice) !ExternalAddress {
    const bits = @as(usize, @intCast(try slice.readUInt(9)));
    var value = [_]u8{0} ** 64;
    try slice.readBitsToBytes(value[0..((bits + 7) / 8)], bits);
    return .{ .bits = bits, .value = value };
}

fn decodeMaybeAnycast(slice: *CellSlice) !?Anycast {
    if (!try slice.readBit()) return null;
    const depth = @as(usize, @intCast(try slice.readUInt(5)));
    if (depth == 0 or depth > 30) return error.DecodeInvalidAnycast;
    var prefix = [_]u8{0} ** 4;
    try slice.readBitsToBytes(prefix[0..((depth + 7) / 8)], depth);
    return .{ .depth = depth, .prefix = prefix };
}

fn decodeCurrencyCollection(slice: *CellSlice) !CurrencyCollection {
    const coins = try decodeCoins(slice);
    const extra_currencies: ExtraCurrencyCollection = if (try slice.readBit())
        .{ .dict_ref = try slice.readRef() }
    else
        .empty;
    return .{
        .coins = coins,
        .extra_currencies = extra_currencies,
    };
}

fn decodeCoins(slice: *CellSlice) !u128 {
    const size = @as(usize, @intCast(try slice.readUInt(4)));
    return slice.readUInt(size * 8);
}

fn dumpBoc(writer: anytype, boc: *const Boc) !void {
    try writer.print("BoC dump\n", .{});
    try writer.print("  magic: 0x{x:0>8} ({s})\n", .{ boc.magic_value, boc.magic.label() });
    try writer.print("  cells: {d}\n", .{boc.cells_count});
    try writer.print("  roots: {d} ", .{boc.roots_count});
    try printIndexList(writer, boc.roots);
    try writer.writeByte('\n');
    try writer.print("  absent: {d}\n", .{boc.absent_count});
    try writer.print("  size_bytes: {d}\n", .{boc.size_bytes});
    try writer.print("  off_bytes: {d}\n", .{boc.off_bytes});
    try writer.print("  total_cell_size: {d}\n", .{boc.total_cell_size});
    try writer.print("  has_idx: {}\n", .{boc.has_idx});
    try writer.print("  has_crc32c: {}\n", .{boc.has_crc32c});
    try writer.print("  has_cache_bits: {}\n", .{boc.has_cache_bits});
    try writer.print("  flags: {d}\n", .{boc.flags});

    if (boc.crc32c_expected) |expected| {
        try writer.print("  crc32c: ok expected=0x{x:0>8} actual=0x{x:0>8}\n", .{ expected, boc.crc32c_actual.? });
    }

    if (boc.index.len > 0) {
        try writer.print("  index: ", .{});
        try printIndexList(writer, boc.index);
        if (boc.index_matches_cells) |matches| {
            try writer.print(" ({s})", .{if (matches) "matches cell ends" else "does not match cell ends"});
        }
        try writer.writeByte('\n');
    }

    try writer.print("  topology: {s}\n", .{if (boc.topology_ok) "ok (refs point to later cells)" else "non-canonical/refers to prior cell"});
    try writer.print("\nCells\n", .{});

    for (boc.cells) |cell| {
        try writer.print("  [{d}] bytes={d}..{d}\n", .{ cell.index, cell.start_offset, cell.end_offset });
        try writer.print("    descriptor: d1=0x{x:0>2} d2=0x{x:0>2}\n", .{ cell.d1, cell.d2 });
        try writer.print("    refs_count: {d}\n", .{cell.refs_count});
        try writer.print("    kind: {s}\n", .{cell.kind.label()});
        try writer.print("    exotic: {}\n", .{cell.exotic});
        try writer.print("    has_hashes: {}\n", .{cell.has_hashes});
        try writer.print("    level_mask: {d}\n", .{cell.level_mask});
        try writer.print("    depth: {d}\n", .{cell.computed_depths[3]});
        try writer.print("    hash: ", .{});
        try printHex(writer, &cell.computed_hashes[3]);
        try writer.writeByte('\n');

        if (cell.has_hashes) {
            try writer.print("    hashes_count: {d}\n", .{cell.hashes_count});
            var i: usize = 0;
            while (i < cell.hashes_count) : (i += 1) {
                try writer.print("    hash[{d}]: ", .{i});
                try printHex(writer, cell.hashes[i * 32 .. (i + 1) * 32]);
                try writer.writeByte('\n');
            }
            try writer.print("    depths: ", .{});
            try printHex(writer, cell.depths);
            try writer.writeByte('\n');
        }

        try writer.print("    data_bits: {d}\n", .{cell.data_bits});
        try writer.print("    padding_added: {}\n", .{cell.padding_added});
        try writer.print("    data_bytes: ", .{});
        try printHex(writer, cell.data_bytes);
        try writer.writeByte('\n');
        try writer.print("    bits: ", .{});
        try printBits(writer, cell.data_bytes, cell.data_bits, 256);
        try writer.writeByte('\n');
        try writer.print("    refs: ", .{});
        try printIndexList(writer, cell.refs);
        try writer.writeByte('\n');
    }
}

fn dumpBocJson(writer: anytype, boc: *const Boc, decode: ?DecodeKind) !void {
    try writer.writeAll("{\n");
    try writer.print("  \"magic\":\"0x{x:0>8}\",\n", .{boc.magic_value});
    try writer.print("  \"magic_kind\":", .{});
    try printJsonString(writer, boc.magic.label());
    try writer.writeAll(",\n");
    try writer.print("  \"cells\":{d},\n", .{boc.cells_count});
    try writer.print("  \"roots\":", .{});
    try printJsonIntArray(writer, boc.roots);
    try writer.writeAll(",\n");
    try writer.print("  \"absent\":{d},\n", .{boc.absent_count});
    try writer.print("  \"size_bytes\":{d},\n", .{boc.size_bytes});
    try writer.print("  \"off_bytes\":{d},\n", .{boc.off_bytes});
    try writer.print("  \"total_cell_size\":{d},\n", .{boc.total_cell_size});
    try writer.print("  \"has_idx\":{},\n", .{boc.has_idx});
    try writer.print("  \"has_crc32c\":{},\n", .{boc.has_crc32c});
    try writer.print("  \"has_cache_bits\":{},\n", .{boc.has_cache_bits});
    try writer.print("  \"flags\":{d},\n", .{boc.flags});
    try writer.print("  \"topology_ok\":{},\n", .{boc.topology_ok});
    try writer.print("  \"index\":", .{});
    try printJsonIntArray(writer, boc.index);
    try writer.writeAll(",\n");
    if (boc.crc32c_expected) |expected| {
        try writer.print("  \"crc32c\":{{\"ok\":true,\"expected\":\"0x{x:0>8}\",\"actual\":\"0x{x:0>8}\"}},\n", .{ expected, boc.crc32c_actual.? });
    } else {
        try writer.writeAll("  \"crc32c\":null,\n");
    }
    try writer.writeAll("  \"cell_list\":[\n");
    for (boc.cells, 0..) |cell, i| {
        if (i != 0) try writer.writeAll(",\n");
        try writer.print("    {{\"index\":{d},\"byte_start\":{d},\"byte_end\":{d},", .{ cell.index, cell.start_offset, cell.end_offset });
        try writer.print("\"kind\":", .{});
        try printJsonString(writer, cell.kind.label());
        try writer.print(",\"descriptor\":{{\"d1\":\"0x{x:0>2}\",\"d2\":\"0x{x:0>2}\"}},", .{ cell.d1, cell.d2 });
        try writer.print("\"refs_count\":{d},\"exotic\":{},\"has_hashes\":{},\"level_mask\":{d},", .{ cell.refs_count, cell.exotic, cell.has_hashes, cell.level_mask });
        try writer.print("\"depth\":{d},\"hash\":", .{cell.computed_depths[3]});
        try printJsonHexString(writer, &cell.computed_hashes[3]);
        try writer.print(",\"data_bits\":{d},\"padding_added\":{},\"data_bytes\":", .{ cell.data_bits, cell.padding_added });
        try printJsonHexString(writer, cell.data_bytes);
        try writer.print(",\"refs\":", .{});
        try printJsonIntArray(writer, cell.refs);
        try writer.writeByte('}');
    }
    try writer.writeAll("\n  ]");
    if (decode) |kind| {
        try writer.writeAll(",\n  \"decode\":");
        try dumpDecodeJson(writer, boc, kind);
    }
    try writer.writeAll("\n}\n");
}

fn dumpDecodeJson(writer: anytype, boc: *const Boc, decode: DecodeKind) !void {
    switch (decode) {
        .message => {
            const message = try decodeMessage(boc);
            try dumpDecodedMessageJson(writer, &message);
        },
    }
}

fn dumpDecodedMessageJson(writer: anytype, message: *const DecodedMessage) !void {
    try writer.print("{{\"kind\":\"message\",\"root\":{d},\"message\":{{", .{message.root});
    try writer.writeAll("\"info\":");
    try dumpMessageInfoJson(writer, &message.info);
    try writer.writeAll(",\"init\":");
    try dumpStateInitLocationJson(writer, message.init);
    try writer.writeAll(",\"body\":");
    try dumpBodyLocationJson(writer, message.body);
    try writer.writeAll("}}");
}

fn dumpMessageInfoJson(writer: anytype, info: *const MessageInfo) !void {
    switch (info.*) {
        .internal => |internal| {
            try writer.writeAll("{\"type\":\"internal\"");
            try writer.print(",\"ihr_disabled\":{},\"bounce\":{},\"bounced\":{}", .{ internal.ihr_disabled, internal.bounce, internal.bounced });
            try writer.writeAll(",\"src\":");
            try dumpAddressJson(writer, internal.src);
            try writer.writeAll(",\"dest\":");
            try dumpAddressJson(writer, internal.dest);
            try writer.writeAll(",\"value\":");
            try dumpCurrencyCollectionJson(writer, internal.value);
            try writer.writeAll(",\"ihr_fee\":");
            try printJsonDecimalString(writer, internal.ihr_fee);
            try writer.writeAll(",\"forward_fee\":");
            try printJsonDecimalString(writer, internal.forward_fee);
            try writer.writeAll(",\"created_lt\":");
            try printJsonDecimalString(writer, internal.created_lt);
            try writer.print(",\"created_at\":{d}", .{internal.created_at});
            try writer.writeByte('}');
        },
        .external_in => |external_in| {
            try writer.writeAll("{\"type\":\"external-in\",\"src\":");
            try dumpAddressJson(writer, external_in.src);
            try writer.writeAll(",\"dest\":");
            try dumpAddressJson(writer, external_in.dest);
            try writer.writeAll(",\"import_fee\":");
            try printJsonDecimalString(writer, external_in.import_fee);
            try writer.writeByte('}');
        },
        .external_out => |external_out| {
            try writer.writeAll("{\"type\":\"external-out\",\"src\":");
            try dumpAddressJson(writer, external_out.src);
            try writer.writeAll(",\"dest\":");
            try dumpAddressJson(writer, external_out.dest);
            try writer.writeAll(",\"created_lt\":");
            try printJsonDecimalString(writer, external_out.created_lt);
            try writer.print(",\"created_at\":{d}", .{external_out.created_at});
            try writer.writeByte('}');
        },
    }
}

fn dumpAddressJson(writer: anytype, address: DecodedAddress) !void {
    switch (address) {
        .none => try writer.writeAll("{\"type\":\"none\"}"),
        .internal => |internal| {
            try writer.print("{{\"type\":\"internal\",\"workchain\":{d},\"hash\":", .{internal.workchain});
            try printJsonHexString(writer, &internal.hash);
            try writer.writeAll(",\"anycast\":");
            try dumpAnycastJson(writer, internal.anycast);
            try writer.writeByte('}');
        },
        .external => |external| {
            try writer.print("{{\"type\":\"external\",\"bits\":{d},\"value\":", .{external.bits});
            try printJsonHexString(writer, external.value[0..((external.bits + 7) / 8)]);
            try writer.writeByte('}');
        },
    }
}

fn dumpAnycastJson(writer: anytype, anycast: ?Anycast) !void {
    if (anycast) |value| {
        try writer.print("{{\"depth\":{d},\"prefix\":", .{value.depth});
        try printJsonHexString(writer, value.prefix[0..((value.depth + 7) / 8)]);
        try writer.writeByte('}');
    } else {
        try writer.writeAll("null");
    }
}

fn dumpCurrencyCollectionJson(writer: anytype, value: CurrencyCollection) !void {
    try writer.writeAll("{\"coins\":");
    try printJsonDecimalString(writer, value.coins);
    try writer.writeAll(",\"extra_currencies\":");
    switch (value.extra_currencies) {
        .empty => try writer.writeAll("{\"present\":false}"),
        .dict_ref => |ref| try writer.print("{{\"present\":true,\"root\":{d}}}", .{ref}),
    }
    try writer.writeByte('}');
}

fn dumpStateInitLocationJson(writer: anytype, init: StateInitLocation) !void {
    switch (init) {
        .none => try writer.writeAll("null"),
        .ref => |ref| try writer.print("{{\"storage\":\"ref\",\"root\":{d}}}", .{ref}),
    }
}

fn dumpBodyLocationJson(writer: anytype, body: BodyLocation) !void {
    switch (body) {
        .in_place => |in_place| try writer.print("{{\"storage\":\"inline\",\"bits\":{d},\"refs\":{d}}}", .{ in_place.bits, in_place.refs }),
        .ref => |ref| try writer.print("{{\"storage\":\"ref\",\"root\":{d}}}", .{ref}),
    }
}

fn printIndexList(writer: anytype, items: []const usize) !void {
    try writer.writeByte('[');
    for (items, 0..) |item, i| {
        if (i != 0) try writer.writeAll(", ");
        try writer.print("{d}", .{item});
    }
    try writer.writeByte(']');
}

fn printJsonIntArray(writer: anytype, items: []const usize) !void {
    try writer.writeByte('[');
    for (items, 0..) |item, i| {
        if (i != 0) try writer.writeByte(',');
        try writer.print("{d}", .{item});
    }
    try writer.writeByte(']');
}

fn printJsonString(writer: anytype, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |byte| {
        switch (byte) {
            '\\' => try writer.writeAll("\\\\"),
            '"' => try writer.writeAll("\\\""),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => try writer.writeByte(byte),
        }
    }
    try writer.writeByte('"');
}

fn printJsonHexString(writer: anytype, bytes: []const u8) !void {
    try writer.writeByte('"');
    for (bytes) |byte| {
        try writer.print("{x:0>2}", .{byte});
    }
    try writer.writeByte('"');
}

fn printJsonDecimalString(writer: anytype, value: u128) !void {
    try writer.print("\"{d}\"", .{value});
}

fn printHex(writer: anytype, bytes: []const u8) !void {
    if (bytes.len == 0) {
        try writer.writeAll("(empty)");
        return;
    }
    for (bytes) |byte| {
        try writer.print("{x:0>2}", .{byte});
    }
}

fn printBits(writer: anytype, bytes: []const u8, bit_len: usize, max_bits: usize) !void {
    if (bit_len == 0) {
        try writer.writeAll("(empty)");
        return;
    }
    const shown = @min(bit_len, max_bits);
    var i: usize = 0;
    while (i < shown) : (i += 1) {
        const byte = bytes[i / 8];
        const shift = @as(u3, @intCast(7 - (i % 8)));
        const bit = (byte >> shift) & 1;
        try writer.writeByte(if (bit == 1) '1' else '0');
    }
    if (shown < bit_len) {
        try writer.print("... ({d} bits total)", .{bit_len});
    }
}

test "crc32c uses Castagnoli/iSCSI test vector" {
    try std.testing.expectEqual(@as(u32, 0xe3069283), std.hash.crc.Crc32Iscsi.hash("123456789"));
}

test "parse single empty cell BoC" {
    const hex = "b5ee9c72010101010002000000";
    var buf: [hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&buf, hex);

    var boc = try parseBoc(std.testing.allocator, &buf);
    defer boc.deinit();

    try std.testing.expectEqual(Magic.generic, boc.magic);
    try std.testing.expectEqual(@as(usize, 1), boc.cells_count);
    try std.testing.expectEqual(@as(usize, 1), boc.roots_count);
    try std.testing.expectEqual(@as(usize, 0), boc.roots[0]);
    try std.testing.expectEqual(@as(usize, 2), boc.total_cell_size);
    try std.testing.expectEqual(@as(usize, 0), boc.cells[0].data_bits);
    try std.testing.expectEqual(@as(usize, 0), boc.cells[0].refs.len);
    try std.testing.expectEqual(@as(u16, 0), boc.cells[0].computed_depths[3]);
    try expectHex(&boc.cells[0].computed_hashes[3], "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7");
}

test "parse indexed BoC with one padded root bitstring and one ref" {
    const hex = "b5ee9c72810102010007000407010160010002fe";
    var buf: [hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&buf, hex);

    var boc = try parseBoc(std.testing.allocator, &buf);
    defer boc.deinit();

    try std.testing.expect(boc.has_idx);
    try std.testing.expectEqual(@as(usize, 2), boc.cells_count);
    try std.testing.expectEqual(@as(usize, 0), boc.roots[0]);
    try std.testing.expectEqual(@as(usize, 4), boc.index[0]);
    try std.testing.expectEqual(@as(usize, 7), boc.index[1]);
    try std.testing.expectEqual(true, boc.index_matches_cells.?);
    try std.testing.expect(boc.topology_ok);
    try std.testing.expectEqual(@as(usize, 2), boc.cells[0].data_bits);
    try std.testing.expectEqual(@as(u8, 0x60), boc.cells[0].data_bytes[0]);
    try std.testing.expectEqual(@as(usize, 1), boc.cells[0].refs[0]);
    try std.testing.expectEqual(@as(usize, 8), boc.cells[1].data_bits);
    try std.testing.expectEqual(@as(u8, 0xfe), boc.cells[1].data_bytes[0]);
    try std.testing.expectEqual(@as(u16, 1), boc.cells[0].computed_depths[3]);
    try std.testing.expectEqual(@as(u16, 0), boc.cells[1].computed_depths[3]);
    try expectHex(&boc.cells[0].computed_hashes[3], "7b71c265d365a005fb3fd0fddc501cab5e27cf473614cc892fec67e14640e1cc");
    try expectHex(&boc.cells[1].computed_hashes[3], "21e65c2337984bf8f8b4415601c9438be8f19b3f3b5c8c77112900c498b5c956");
}

test "parse @ton/core generated fixture" {
    const hex = "b5ee9c7201010201000f000110000000000000000001000401c8";
    var buf: [hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&buf, hex);

    var boc = try parseBoc(std.testing.allocator, &buf);
    defer boc.deinit();

    try std.testing.expectEqual(@as(usize, 2), boc.cells_count);
    try std.testing.expectEqual(@as(usize, 64), boc.cells[0].data_bits);
    try std.testing.expectEqual(@as(usize, 16), boc.cells[1].data_bits);
    try std.testing.expectEqual(@as(u16, 1), boc.cells[0].computed_depths[3]);
    try std.testing.expectEqual(@as(u16, 0), boc.cells[1].computed_depths[3]);
    try expectHex(&boc.cells[0].computed_hashes[3], "3fff0abddb5c8536d4015a08d22a7e16e73dac5d04d12ada73274900ea65ba93");
    try expectHex(&boc.cells[1].computed_hashes[3], "c6b68699361fd51dcf64d97ccd926801fd84bc87712e21aa3633e40c1b3760a2");
}

test "decode @ton/core external-in message" {
    const hex = "b5ee9c720101010100250000458800222222222222222222222222222222222222222222222222222222222222222204";
    var buf: [hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&buf, hex);

    var boc = try parseBoc(std.testing.allocator, &buf);
    defer boc.deinit();

    const message = try decodeMessage(&boc);
    try std.testing.expectEqual(@as(usize, 0), message.root);
    switch (message.info) {
        .external_in => |info| {
            switch (info.src) {
                .none => {},
                else => return error.TestExpectedEmptyExternalSource,
            }
            switch (info.dest) {
                .internal => |dest| {
                    try std.testing.expectEqual(@as(i16, 0), dest.workchain);
                    try expectHex(&dest.hash, "1111111111111111111111111111111111111111111111111111111111111111");
                },
                else => return error.TestExpectedInternalDestination,
            }
            try std.testing.expectEqual(@as(u128, 0), info.import_fee);
        },
        else => return error.TestExpectedExternalInMessage,
    }
    try std.testing.expectEqual(StateInitLocation.none, message.init);
    switch (message.body) {
        .in_place => |body| {
            try std.testing.expectEqual(@as(usize, 0), body.bits);
            try std.testing.expectEqual(@as(usize, 0), body.refs);
        },
        else => return error.TestExpectedInlineBody,
    }
}

test "decode @ton/core internal message" {
    const hex = "b5ee9c7201010101005c0000b3680044444444444444444444444444444444444444444444444444444444444444453fccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccd01d6f34540000000000000000540000000e55e6f780c0";
    var buf: [hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&buf, hex);

    var boc = try parseBoc(std.testing.allocator, &buf);
    defer boc.deinit();

    const message = try decodeMessage(&boc);
    switch (message.info) {
        .internal => |info| {
            try std.testing.expect(info.ihr_disabled);
            try std.testing.expect(info.bounce);
            try std.testing.expect(!info.bounced);
            switch (info.src) {
                .internal => |src| {
                    try std.testing.expectEqual(@as(i16, 0), src.workchain);
                    try expectHex(&src.hash, "2222222222222222222222222222222222222222222222222222222222222222");
                },
                else => return error.TestExpectedInternalSource,
            }
            switch (info.dest) {
                .internal => |dest| {
                    try std.testing.expectEqual(@as(i16, -1), dest.workchain);
                    try expectHex(&dest.hash, "3333333333333333333333333333333333333333333333333333333333333333");
                },
                else => return error.TestExpectedInternalDestination,
            }
            try std.testing.expectEqual(@as(u128, 123456789), info.value.coins);
            try std.testing.expectEqual(ExtraCurrencyCollection.empty, info.value.extra_currencies);
            try std.testing.expectEqual(@as(u128, 0), info.ihr_fee);
            try std.testing.expectEqual(@as(u128, 0), info.forward_fee);
            try std.testing.expectEqual(@as(u128, 42), info.created_lt);
            try std.testing.expectEqual(@as(u64, 7), info.created_at);
        },
        else => return error.TestExpectedInternalMessage,
    }
    switch (message.body) {
        .in_place => |body| {
            try std.testing.expectEqual(@as(usize, 32), body.bits);
            try std.testing.expectEqual(@as(usize, 0), body.refs);
        },
        else => return error.TestExpectedInlineBody,
    }
}

test "parse generic BoC with CRC32C" {
    const no_crc_hex = "b5ee9c72410101010002000000";
    var no_crc: [no_crc_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&no_crc, no_crc_hex);

    const crc = std.hash.crc.Crc32Iscsi.hash(&no_crc);
    var bytes: [no_crc.len + 4]u8 = undefined;
    @memcpy(bytes[0..no_crc.len], &no_crc);
    std.mem.writeInt(u32, bytes[no_crc.len..][0..4], crc, .little);

    var boc = try parseBoc(std.testing.allocator, &bytes);
    defer boc.deinit();

    try std.testing.expect(boc.has_crc32c);
    try std.testing.expectEqual(crc, boc.crc32c_expected.?);
    try std.testing.expectEqual(crc, boc.crc32c_actual.?);
}

test "reject invalid CRC32C" {
    const hex = "b5ee9c7241010101000200000000000000";
    var buf: [hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&buf, hex);

    try std.testing.expectError(error.InvalidCrc32c, parseBoc(std.testing.allocator, &buf));
}

test "reject non-canonical backwards ref" {
    const hex = "b5ee9c728101020100070003070002fe01016000";
    var buf: [hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&buf, hex);

    try std.testing.expectError(error.InvalidTopologicalOrder, parseBoc(std.testing.allocator, &buf));
}

test "decode CLI options" {
    const args = [_][:0]const u8{ "bocdump", "--json", "--decode", "message", "--hex", "00" };
    const options = try parseArgs(&args);
    try std.testing.expectEqual(OutputMode.json, options.output);
    try std.testing.expectEqual(DecodeKind.message, options.decode.?);
    try std.testing.expectEqual(InputKind.hex, options.input_kind.?);
    try std.testing.expectEqualStrings("00", options.input_value.?);
}

fn expectHex(bytes: []const u8, expected_hex: []const u8) !void {
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    try std.testing.expectEqualSlices(u8, &expected, bytes);
}

pub fn containsScalar(comptime T: type, slice: []const T, value: T) bool {
    for (slice) |v| {
        if (v == value) return true;
    }
    return false;
}

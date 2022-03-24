const std = @import("std");
const datetime = @import("datetime");
const Datetime = datetime.datetime.Datetime;

pub const TimestampSeconds = struct {
    seconds: i64,

    pub fn fromDatetime(dt: Datetime) TimestampSeconds {
        return .{ .seconds = @intCast(i64, @divTrunc(dt.toTimestamp(), std.time.ms_per_s)) };
    }

    pub fn toDatetime(self: TimestampSeconds) Datetime {
        return Datetime.fromTimestamp(self.seconds * std.time.ms_per_s);
    }

    pub fn now() TimestampSeconds {
        return .{ .seconds = std.time.timestamp() };
    }

    pub fn add(self: TimestampSeconds, delta: DeltaSeconds) TimestampSeconds {
        return .{ .seconds = self.seconds + delta.seconds };
    }

    pub fn sub(self: TimestampSeconds, other: TimestampSeconds) DeltaSeconds {
        return .{ .seconds = self.seconds - other.seconds };
    }

    pub fn order(self: TimestampSeconds, other: TimestampSeconds) std.math.Order {
        return std.math.order(self.seconds, other.seconds);
    }
};

pub const DeltaSeconds = struct {
    seconds: i64,

    pub fn fromSeconds(seconds: anytype) DeltaSeconds {
        return .{ .seconds = @intCast(i64, seconds) };
    }

    pub fn order(self: DeltaSeconds, other: DeltaSeconds) std.math.Order {
        return std.math.order(self.seconds, other.seconds);
    }
};

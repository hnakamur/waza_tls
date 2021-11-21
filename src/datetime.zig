const std = @import("std");
const datetime = @import("datetime");

pub fn writeDatetimeHeader(writer: anytype, header_name: []const u8, dt: datetime.datetime.Datetime) !void {
    try std.fmt.format(writer, "{s}: ", .{header_name});
    try formatDatetime(writer, dt);
    try std.fmt.format(writer, "\r\n", .{});
}

fn formatDatetime(writer: anytype, dt: datetime.datetime.Datetime) !void {
    const dt_gmt = dt.shiftTimezone(&datetime.timezones.GMT);
    try std.fmt.format(writer, "{s}, {d} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} {s}", .{
        dt_gmt.date.weekdayName()[0..3],
        dt_gmt.date.day,
        dt_gmt.date.monthName()[0..3],
        dt_gmt.date.year,
        dt_gmt.time.hour,
        dt_gmt.time.minute,
        dt_gmt.time.second,
        dt_gmt.zone.name,
    });
}

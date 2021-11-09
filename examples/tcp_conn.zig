const std = @import("std");
const time = std.time;
const IO = @import("tigerbeetle-io").IO;
const http = @import("http");
const TCPConn = @import("http").TCPConn;

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const port = 3131;

    var io = try IO.init(32, 0);
    defer io.deinit();
    const address = try std.net.Address.parseIp4("127.0.0.1", port);

    var conn = try TCPConn.init(&io, address);
    defer conn.deinit();

    const MyContext = struct {
        conn: TCPConn,
        completion: TCPConn.Completion = undefined,
        send_buf: [1024]u8 = [_]u8{0} ** 1024,
        recv_buf: [1024]u8 = [_]u8{0} ** 1024,
        connect_timeout: u63 = 500 * time.ns_per_ms,
        send_timeout: u63 = 500 * time.ns_per_ms,
        recv_timeout: u63 = 500 * time.ns_per_ms,
        done: bool = false,

        const Self = @This();

        fn connect(self: *Self) void {
            self.conn.connectWithTimeout(
                *Self,
                self,
                connectCallback,
                &self.completion,
                self.connect_timeout,
            );
        }
        fn connectCallback(
            self: *Self,
            comp: *TCPConn.Completion,
            result: TCPConn.ConnectError!void,
        ) void {
            std.debug.print("MyContext.connectCallback, result={}\n", .{result});

            var fbs = std.io.fixedBufferStream(&self.send_buf);
            var w = fbs.writer();
            std.fmt.format(w, "{s} {s} {s}\r\n", .{
                (http.Method{ .get = undefined }).toText(),
                "/",
                http.Version.http1_1.toText(),
            }) catch unreachable;
            std.fmt.format(w, "Host: example.com\r\n\r\n", .{}) catch unreachable;
            self.conn.sendWithTimeout(
                *Self,
                self,
                sendCallback,
                &self.completion,
                fbs.getWritten(),
                self.send_timeout,
            );
        }
        fn sendCallback(
            self: *Self,
            comp: *TCPConn.Completion,
            result: TCPConn.SendError!usize,
        ) void {
            std.debug.print("MyContext.sendCallback, result={}\n", .{result});
            self.conn.recvWithTimeout(
                *Self,
                self,
                recvCallback,
                &self.completion,
                &self.recv_buf,
                self.recv_timeout,
            );
        }
        fn recvCallback(
            self: *Self,
            comp: *TCPConn.Completion,
            result: TCPConn.RecvError!usize,
        ) void {
            std.debug.print("MyContext.recvCallback, result={}\n", .{result});
            if (result) |received| {
                std.debug.print("response={s}", .{self.recv_buf[0..received]});
            } else |err| {
                std.debug.print("MyContext.recvCallback, err={s}\n", .{@errorName(err)});
            }
            self.done = true;
        }
    };

    var ctx = MyContext{ .conn = conn };
    ctx.connect();
    while (!ctx.done) {
        try io.run_for_ns(time.ns_per_s);
    }
}

const IO = @import("tigerbeetle-io").IO;

test "ClientHandler" {
    var io = try IO.init(1, 0);
    defer io.deinit();
}
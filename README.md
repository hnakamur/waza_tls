hutaback
========

hutaback is an experimental HTTP library using io_uring.
It is written in Zig.
However it does use the zig's async/await.
It uses callbacks instead.

This project is meant for me to learn callback style programming using io_uring.
I'd like to see whether it is reasonable for me to write and maintain callback-based code.
Also I'd like to see the performance difference, such as latency, throughtput, and memory footprint.

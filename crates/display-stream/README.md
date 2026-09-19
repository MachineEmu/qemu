# Display streamer

`display-stream` reads QEMU display callbacks and supplies H.264 video to the
web proxy. The production encoder is GStreamer's `vah264enc`.

The encoder's stdout uses `multipartmux` with a content length per access unit.
This preserves frame boundaries across pipe reads and delivers the final frame
without waiting for another frame. The web socket record format is unchanged.
The GStreamer good plugins package must be available for `multipartmux`.

Raw frames are fed at 60 fps, including while the desktop is static. Encoder
stdin and stdout are handled independently. Viewers receive a bounded cached
sequence containing the codec configuration, the latest IDR, and every following
delta frame. Subscription and cache reads are atomic. The existing `request_idr`
control message requests a replay of this complete sequence; it does not send a
force-key-unit event to the encoder. If the cache has exceeded its 32 MiB limit,
viewers wait for the next periodic IDR. Lagging viewers resynchronize the same way.

Resolution changes finalize and reap the previous encoder before starting a new
recording segment. The first segment uses the supplied recording path (normally
`screen.mp4`); subsequent segments use `screen-0001.mp4`, `screen-0002.mp4`, etc.
SIGINT and SIGTERM also finalize the current segment. Forced termination after a
shutdown timeout may leave that segment incomplete and is reported as an error.

Input forwarding runs separately from video processing. Its queue holds at most
256 messages and coalesces only adjacent absolute pointer movements, preserving
the ordering around button and key events. Queue overflow disconnects the viewer;
D-Bus errors and timeouts are logged.

Run unit tests with `cargo test -p display-stream`. The integration test requires
GStreamer (including `openh264enc`, `h264parse`, `multipartmux`, and `mp4mux`) and
FFmpeg:

```sh
cargo test -p display-stream -- --include-ignored
```

The integration test uses software H.264 to test pipe handling, static-frame
keyframes, recording segments, and independent decoding without a GPU. A live
QEMU/VA-API session remains necessary to validate capture and hardware encoding.

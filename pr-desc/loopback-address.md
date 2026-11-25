Enrollment can now use plain HTTP on the server Mac without certificate setup. Protocol 0.3.0 adds the `loopback` address kind with host `localhost` and a required port. LAN and tailnet addresses keep their existing HTTPS rules.

The CLI workspace uses the new protocol version. Typecheck, lint, build and tests pass. The local tarball is packed for the server and cloud repositories. Nothing was published to npm.

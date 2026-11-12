(module
  ;; A deterministic probe for the record/replay endpoints: it draws four
  ;; random_get bytes and echoes them verbatim to stdout, so a successful
  ;; replay's stdout must equal the recorded bytes on every run and any
  ;; tampering with a recorded byte changes the output and fails the
  ;; byte-for-byte comparison.
  (import "wasi_snapshot_preview1" "random_get"
    (func $random_get (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))

  (memory (export "memory") 1)

  (func (export "_start")
    ;; Fetch four random bytes at address 4096 and echo them to stdout.
    (drop (call $random_get (i32.const 4096) (i32.const 4)))
    (i32.store (i32.const 0) (i32.const 4096))
    (i32.store (i32.const 4) (i32.const 4))
    (drop (call $fd_write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))
  )
)

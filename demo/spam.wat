(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))

  (memory (export "memory") 1)
  (data (i32.const 1024) "{\"verdict\":\"allow\",\"source\":\"spam-demo\"}\n")

  ;; A plugin that writes without end. The parent's combined stdout+stderr
  ;; ceiling must kill it before any partial result can be returned.
  (func (export "_start")
    (loop $forever
      (i32.store (i32.const 0) (i32.const 1024))
      (i32.store (i32.const 4) (i32.const 41))
      (drop (call $fd_write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))
      (br $forever)
    )
  )
)

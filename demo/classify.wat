(module
  (import "wasi_snapshot_preview1" "fd_read"
    (func $fd_read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))

  (memory (export "memory") 2)
  (global $total (mut i32) (i32.const 0))
  (global $buf i32 (i32.const 8192))

  ;; JSON verdicts, each written only after the entire stdin has been consumed.
  (data (i32.const 1024) "{\"verdict\":\"allow\",\"score\":0,\"reasons\":[\"no malicious marker found\"]}")
  (data (i32.const 2048) "{\"verdict\":\"review\",\"score\":55,\"reasons\":[\"suspicious marker found\"]}")
  (data (i32.const 3072) "{\"verdict\":\"block\",\"score\":95,\"reasons\":[\"malicious marker found\"]}")

  ;; Demo markers. A real plugin would parse the JSON; this tiny module uses
  ;; byte-substring matching solely so the sandbox demo stays dependency-free.
  (data (i32.const 4096) "malicious")
  (data (i32.const 4120) "suspicious")

  ;; Read all of stdin (up to 64 KiB) into the buffer at 8192.
  (func $read_input
    (local $pos i32)
    (local $n i32)
    (block $done
      (loop $read
        (i32.store (i32.const 0)
          (i32.add (global.get $buf) (local.get $pos)))
        (i32.store (i32.const 4)
          (i32.sub (i32.const 65536) (local.get $pos)))
        (drop (call $fd_read (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 8)))
        (local.set $n (i32.load (i32.const 8)))
        (local.set $pos (i32.add (local.get $pos) (local.get $n)))
        (br_if $done (i32.eqz (local.get $n)))
        (br_if $done (i32.ge_u (local.get $pos) (i32.const 65536)))
        (br $read)
      )
    )
    (global.set $total (local.get $pos))
  )

  ;; Write a NUL-free string to stdout.
  (func $write_str (param $ptr i32) (param $len i32)
    (i32.store (i32.const 16) (local.get $ptr))
    (i32.store (i32.const 20) (local.get $len))
    (drop (call $fd_write (i32.const 1) (i32.const 16) (i32.const 1) (i32.const 24)))
  )

  ;; Return 1 when needle[pos..pos+nlen] equals the needle.
  (func $match_at (param $pos i32) (param $needle i32) (param $nlen i32) (result i32)
    (local $j i32)
    (block $out (result i32)
      (loop $cmp
        (br_if $out (i32.const 1)
          (i32.ge_u (local.get $j) (local.get $nlen)))
        (br_if $out (i32.const 0)
          (i32.ne
            (i32.load8_u
              (i32.add (global.get $buf)
                (i32.add (local.get $pos) (local.get $j))))
            (i32.load8_u
              (i32.add (local.get $needle) (local.get $j)))))
        (local.set $j (i32.add (local.get $j) (i32.const 1)))
        (br $cmp)
      )
      (unreachable)
    )
  )

  ;; Return 1 when stdin contains the marker.
  (func $contains (param $needle i32) (param $nlen i32) (result i32)
    (local $i i32)
    (local $last i32)
    (if (i32.lt_u (global.get $total) (local.get $nlen))
      (then (return (i32.const 0))))
    (local.set $last (i32.sub (global.get $total) (local.get $nlen)))
    (block $not_found (result i32)
      (loop $scan
        (br_if $not_found (i32.const 0)
          (i32.gt_u (local.get $i) (local.get $last)))
        (br_if $not_found (i32.const 1)
          (call $match_at (local.get $i)
            (local.get $needle) (local.get $nlen)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $scan)
      )
      (unreachable)
    )
  )

  (func (export "_start")
    (call $read_input)
    (if (call $contains (i32.const 4096) (i32.const 9))
      (then
        (call $write_str (i32.const 3072) (i32.const 67))
        (return)))
    (if (call $contains (i32.const 4120) (i32.const 10))
      (then
        (call $write_str (i32.const 2048) (i32.const 69))
        (return)))
    (call $write_str (i32.const 1024) (i32.const 69))
  )
)

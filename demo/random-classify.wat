(module
  (import "wasi_snapshot_preview1" "fd_read"
    (func $fd_read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "random_get"
    (func $random_get (param i32 i32) (result i32)))

  (memory (export "memory") 2)
  (global $total (mut i32) (i32.const 0))
  (global $buf i32 (i32.const 8192))

  ;; JSON verdicts written to stdout.
  (data (i32.const 1024) "{\"verdict\":\"allow\",\"score\":0,\"source\":\"random-classify\"}")
  (data (i32.const 2048) "{\"verdict\":\"review\",\"score\":55,\"source\":\"random-classify\"}")
  (data (i32.const 3072) "{\"verdict\":\"block\",\"score\":95,\"source\":\"random-classify\"}")

  ;; Demo markers; same byte-substring approach as classify.wat.
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

  ;; Two random_get calls with different lengths, so a recording shows the
  ;; ordered (length, errno, bytes) triples that replay injects.  The first
  ;; byte biases the verdict up or down; the 4-byte word adds a coin-flip.
  (func $roll (result i32)
    (local $byte i32)
    (local $word i32)
    (drop (call $random_get (i32.const 64) (i32.const 1)))
    (drop (call $random_get (i32.const 128) (i32.const 4)))
    (local.set $byte (i32.load8_u (i32.const 64)))
    (local.set $word (i32.load (i32.const 128)))
    ;; Combine into a 0..3 score: high bit of the byte plus low bit of the word.
    (i32.add
      (i32.and (i32.shr_u (local.get $byte) (i32.const 7)) (i32.const 2))
      (i32.and (local.get $word) (i32.const 1)))
  )

  (func (export "_start")
    (local $roll i32)
    (call $read_input)
    (local.set $roll (call $roll))

    ;; Malicious marker: block unless the randomness strongly disagrees (0).
    (if (call $contains (i32.const 4096) (i32.const 9))
      (then
        (if (i32.eq (local.get $roll) (i32.const 0))
          (then (call $write_str (i32.const 2048) (i32.const 58)))
          (else (call $write_str (i32.const 3072) (i32.const 57))))
        (return)))

    ;; Suspicious marker: review unless the coin-flip rolls the lowest value.
    (if (call $contains (i32.const 4120) (i32.const 10))
      (then
        (if (i32.le_u (local.get $roll) (i32.const 1))
          (then (call $write_str (i32.const 1024) (i32.const 56)))
          (else (call $write_str (i32.const 2048) (i32.const 58))))
        (return)))

    ;; Benign input: randomness only flips allow into review.
    (if (i32.eq (local.get $roll) (i32.const 3))
      (then (call $write_str (i32.const 2048) (i32.const 58)))
      (else (call $write_str (i32.const 1024) (i32.const 56))))
  )
)

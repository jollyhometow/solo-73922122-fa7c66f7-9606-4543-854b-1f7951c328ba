(module
  ;; A plugin that never returns. The parent's wall-clock deadline must kill it.
  (func (export "_start")
    (loop $forever
      (br $forever)
    )
  )
)

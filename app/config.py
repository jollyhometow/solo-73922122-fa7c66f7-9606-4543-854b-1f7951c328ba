"""Limits shared by the API and the sandbox supervisor."""

MAX_MODULE_BYTES = 1 * 1024 * 1024
MAX_LOG_BYTES = 64 * 1024
MAX_PLUGIN_OUTPUT_BYTES = 64 * 1024
PLUGIN_TIMEOUT_SECONDS = 2.0
PLUGIN_MEMORY_BYTES = 64 * 1024 * 1024
PLUGIN_TABLE_ELEMENTS = 100_000
PLUGIN_INSTANCES = 1
PLUGIN_TABLES = 1
PLUGIN_MEMORIES = 1

# Recording / replay limits.  A recording may capture at most this many
# random_get calls and at most this many bytes of random payload.  When either
# ceiling is crossed the run is terminated and no package is produced.
MAX_RANDOM_RECORDS = 256
MAX_RANDOM_BYTES = 32 * 1024

# A replay package contains the module, the log, at most MAX_RANDOM_BYTES of
# random payload (base64 expands that by ~4/3) plus framing and hashes.  It is
# always smaller than the module plus its log, but is validated as its own
# upload field with an explicit ceiling.
MAX_PACKAGE_BYTES = MAX_MODULE_BYTES + MAX_LOG_BYTES + 96 * 1024

# Multipart framing is tiny compared with the payloads, but leave room for
# headers and boundaries so the largest allowed fields are accepted.
MAX_REQUEST_BYTES = MAX_MODULE_BYTES + MAX_LOG_BYTES + 192 * 1024
# Replay carries the module, the log and a package; the package embeds a copy
# of the first two, so the body can be roughly twice the payload size.
MAX_REPLAY_REQUEST_BYTES = (
    MAX_MODULE_BYTES + MAX_LOG_BYTES + MAX_PACKAGE_BYTES + 256 * 1024
)

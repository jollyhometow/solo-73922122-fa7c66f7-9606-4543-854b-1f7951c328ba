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

# Multipart framing is tiny compared with the payloads, but leave room for
# headers and boundaries so the largest allowed module and log are accepted.
MAX_REQUEST_BYTES = MAX_MODULE_BYTES + MAX_LOG_BYTES + 192 * 1024

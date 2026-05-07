#ifndef SandblasterBridge_h
#define SandblasterBridge_h

#include <stdint.h>

/// Start a dry-run ARM64 scan. Returns 0 on success, -1 if already running.
int32_t sandblaster_scan_start(int32_t dry_run);

/// Poll for the next SB1 packet line. Writes into out_buf.
/// Returns bytes written (>0), 0 if queue empty and scan running,
/// -1 if scan is done and queue drained, -2 on bad arguments.
int32_t sandblaster_scan_next(uint8_t *out_buf, int32_t buf_len);

/// Signal the running scan to stop (non-blocking signal; waits for thread).
void sandblaster_scan_stop(void);

/// Copy the last error string into out_buf. Returns bytes written, -2 on bad args.
int32_t sandblaster_last_error(uint8_t *out_buf, int32_t buf_len);

#endif /* SandblasterBridge_h */

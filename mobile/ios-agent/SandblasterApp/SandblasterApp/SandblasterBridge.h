#ifndef SandblasterBridge_h
#define SandblasterBridge_h

#include <stdint.h>

/// Start a scan.
/// mode: 0=ARM64 native, 1=ARM64 dry-run, 2=sandbox_check policy fuzzing.
/// Returns 0 on success, -1 if already running.
int32_t sandblaster_scan_start(int32_t mode);

/// Start a configured scan.
/// strategy: 0=tunnel, 1=brute, 2=random, 3=driven-empty.
/// max_packets: 0 means continuous until stopped.
/// queue_capacity: 0 uses the default bounded queue.
/// require_native: nonzero makes native backend setup failure fatal.
int32_t sandblaster_scan_start_config(int32_t mode,
                                      int32_t strategy,
                                      const char *start_hex,
                                      const char *end_hex,
                                      uint64_t seed,
                                      uint64_t max_packets,
                                      uint32_t queue_capacity,
                                      int32_t require_native);

typedef struct SandblasterScanStatus {
    uint32_t running;
    uint32_t done;
    uint64_t emitted;
    uint64_t skipped;
    uint32_t queue_depth;
    uint32_t queue_capacity;
    uint32_t has_error;
} SandblasterScanStatus;

int32_t sandblaster_scan_status(SandblasterScanStatus *out_status);

/// Poll for the next SB1 packet line. Writes into out_buf.
/// Returns bytes written (>0), 0 if queue empty and scan running,
/// -1 if scan is done and queue drained, -2 on bad arguments,
/// -3 if the buffer is too small for the next complete line.
int32_t sandblaster_scan_next(uint8_t *out_buf, int32_t buf_len);

/// Signal the running scan to stop (non-blocking signal; waits for thread).
void sandblaster_scan_stop(void);

/// Copy the last error string into out_buf. Returns bytes written, -2 on bad args.
int32_t sandblaster_last_error(uint8_t *out_buf, int32_t buf_len);

/// Copy the last emitted instruction hex into out_buf.
int32_t sandblaster_last_instruction(uint8_t *out_buf, int32_t buf_len);

#endif /* SandblasterBridge_h */

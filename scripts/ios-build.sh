#!/usr/bin/env bash
# Build the Rust staticlib for iOS ARM64 and copy it into the Xcode project.
set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
TARGET=aarch64-apple-ios
LIB=libsandblaster_mobile_ffi.a
LIBS_DIR="$REPO/mobile/ios-agent/SandblasterApp/libs"

# Ensure the iOS target is installed.
if ! rustup target list --installed 2>/dev/null | grep -q "$TARGET"; then
    echo "Installing Rust target $TARGET..."
    rustup target add "$TARGET"
fi

echo "Building $LIB for $TARGET (release)..."
cargo build \
    --manifest-path "$REPO/Cargo.toml" \
    --target "$TARGET" \
    --release \
    -p sandblaster-mobile-ffi

mkdir -p "$LIBS_DIR"
cp "$REPO/target/$TARGET/release/$LIB" "$LIBS_DIR/"
echo "Copied to $LIBS_DIR/$LIB"
echo ""
echo "Next steps:"
echo "  1. Open mobile/ios-agent/SandblasterApp/SandblasterApp.xcodeproj in Xcode"
echo "  2. Select the SandblasterApp target -> Signing & Capabilities"
echo "  3. Set your Development Team"
echo "  4. Connect a physical iOS device and press Run"
echo "  5. Results are written to the app's Documents folder (sandblaster_results.txt)"
echo "     Retrieve via: Xcode -> Window -> Devices and Simulators -> your device -> Download Container"

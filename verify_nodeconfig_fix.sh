#!/bin/bash
# Quick verification script for NodeConfig fixes

echo "Checking for NodeConfig instances with the required fields..."
echo ""

FILES=(
    "crates/qbind-node/tests/t175_p2p_wiring_smoke_tests.rs"
    "crates/qbind-node/tests/t175_p2p_node_config_tests.rs"
)

for file in "${FILES[@]}"; do
    echo "Checking $file:"
    
    # Count NodeConfig initializations
    config_count=$(grep -c "NodeConfig {" "$file" 2>/dev/null || echo "0")
    
    # Count snapshot_config occurrences
    snapshot_count=$(grep -c "snapshot_config: SnapshotConfig" "$file" 2>/dev/null || echo "0")
    
    # Count fast_sync_config occurrences
    fast_sync_count=$(grep -c "fast_sync_config: FastSyncConfig" "$file" 2>/dev/null || echo "0")
    
    echo "  NodeConfig initializations: $config_count"
    echo "  snapshot_config fields: $snapshot_count"
    echo "  fast_sync_config fields: $fast_sync_count"
    
    if [ "$snapshot_count" -eq "$config_count" ] && [ "$fast_sync_count" -eq "$config_count" ]; then
        echo "  ✓ All instances appear to have the required fields"
    else
        echo "  ✗ Mismatch detected - may need manual review"
    fi
    echo ""
done

echo "Attempting quick syntax check..."
cargo check --test t175_p2p_wiring_smoke_tests --message-format=short 2>&1 | grep -E "^(error|warning:.*E0063)"
if [ $? -ne 0 ]; then
    echo "✓ No E0063 errors found in cargo check output"
fi

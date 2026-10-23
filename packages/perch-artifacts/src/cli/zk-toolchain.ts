#!/usr/bin/env node
// perch-zk-toolchain: scripts/zk-toolchain.sh, installing the pinned nargo and
// bb under ./target/zk-toolchain (or PERCH_ZK_TOOLCHAIN_DIR).
import { runScript } from '../script.js';

runScript('zk-toolchain.sh');

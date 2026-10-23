#!/usr/bin/env node
// perch-fetch-infra-wasm: scripts/fetch-infra-wasm.sh against this package's
// deployments/. Outside a perch checkout it fills only --stack.
import { runScript } from '../script.js';

runScript('fetch-infra-wasm.sh');

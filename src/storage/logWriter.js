const path = require('path');
const { LOGS_DIR } = require('../config');
const { appendJsonl } = require('./file');
const { upsertDeviceRecord } = require('./deviceLedger');

function currentDateTag(now = new Date()) {
    return now.toISOString().slice(0, 10);
}

function buildLogPath(prefix, now) {
    const tag = currentDateTag(now);
    return path.join(LOGS_DIR, `${prefix}_${tag}.jsonl`);
}

function deviceLogPath() {
    return path.join(LOGS_DIR, 'device_attest.jsonl');
}

async function writeAccessLog(event) {
    const now = new Date();
    const payload = {
        ts: now.toISOString(),
        ...event
    };
    await appendJsonl(buildLogPath('access', now), payload);
}

async function writeAuditLog(event) {
    const now = new Date();
    const payload = {
        ts: now.toISOString(),
        ...event
    };
    await appendJsonl(buildLogPath('audit', now), payload);
}

async function writeDeviceAttestLog({ serial, model, snapshot }) {
    if (!serial || !snapshot) {
        return;
    }
    await upsertDeviceRecord(deviceLogPath(), {
        serial,
        model,
        keyDescription: snapshot
    });
}

module.exports = {
    writeAccessLog,
    writeAuditLog,
    writeDeviceAttestLog
};

const fs = require('fs/promises');
const path = require('path');
const { DATA_DIR } = require('../config');
const { ensureDir } = require('./file');

const ROOTS_FILE = path.join(DATA_DIR, 'google-roots.pem');
const STATUS_FILE = path.join(DATA_DIR, 'google-crl.json');

async function loadRoots() {
    try {
        const data = await fs.readFile(ROOTS_FILE, 'utf8');
        try {
            const parsed = JSON.parse(data);
            if (Array.isArray(parsed.certificates)) {
                return parsed.certificates
                    .flatMap(normalizePemEntry)
                    .filter(Boolean);
            }
        } catch (jsonError) {
            // fall back to PEM parsing
        }
        return data
            .split(/\n(?=-----BEGIN CERTIFICATE-----)/g)
            .map((block) => block.trim())
            .filter((block) => block.length > 0);
    } catch (error) {
        if (error.code === 'ENOENT') {
            return [];
        }
        throw error;
    }
}

async function saveRoots(pemList) {
    await ensureDir(path.dirname(ROOTS_FILE));
    const payload = JSON.stringify({ certificates: pemList }, null, 2);
    await fs.writeFile(ROOTS_FILE, payload, 'utf8');
}

function normalizePemEntry(entry) {
    if (!entry) {
        return [];
    }
    if (typeof entry === 'string') {
        const trimmed = entry.trim();
        if (trimmed.startsWith('[')) {
            try {
                const nested = JSON.parse(trimmed);
                if (Array.isArray(nested)) {
                    const pem = nested.join('\n');
                    if (pem.includes('-----BEGIN CERTIFICATE-----')) {
                        return [pem];
                    }
                }
            } catch (error) {
                // ignore and fall through
            }
        }
        if (trimmed.includes('-----BEGIN CERTIFICATE-----')) {
            return [trimmed.replace(/\\n/g, '\n').replace(/\"/g, '"')];
        }
    }
    return [];
}

async function loadStatus() {
    try {
        const data = await fs.readFile(STATUS_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        if (error.code === 'ENOENT') {
            return null;
        }
        throw error;
    }
}

async function saveStatus(status) {
    await ensureDir(path.dirname(STATUS_FILE));
    await fs.writeFile(STATUS_FILE, JSON.stringify(status, null, 2), 'utf8');
}

module.exports = {
    loadRoots,
    saveRoots,
    loadStatus,
    saveStatus,
    ROOTS_FILE,
    STATUS_FILE
};

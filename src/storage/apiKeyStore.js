const crypto = require('crypto');
const path = require('path');
const { DATA_DIR } = require('../config');
const { readJsonFile, writeJsonFileAtomic } = require('./file');

const STORE_FILE = path.join(DATA_DIR, 'api-keys.json');

function deriveHash(secret, salt) {
    return crypto.pbkdf2Sync(secret, salt, 120000, 64, 'sha512').toString('hex');
}

async function loadStore() {
    const data = await readJsonFile(STORE_FILE, null);
    if (data && Array.isArray(data.keys)) {
        return data;
    }
    return { keys: [] };
}

async function saveStore(store) {
    await writeJsonFileAtomic(STORE_FILE, store);
}

function sanitizeKey(key) {
    const { hash, salt, secretPreview, ...rest } = key;
    return {
        ...rest,
        preview: secretPreview || null,
        disabled: Boolean(key.disabled)
    };
}

async function listKeys() {
    const store = await loadStore();
    return store.keys.map(sanitizeKey);
}

async function createKey(label) {
    const normalizedLabel = (label || '').trim();
    if (!normalizedLabel) {
        const error = new Error('Label required');
        error.code = 'LABEL_REQUIRED';
        throw error;
    }

    const store = await loadStore();
    const exists = store.keys.some((entry) => {
        const entryLabel = (entry.label || '').trim().toLowerCase();
        return entryLabel === normalizedLabel.toLowerCase();
    });

    if (exists) {
        const error = new Error('Label already exists');
        error.code = 'LABEL_EXISTS';
        throw error;
    }

    const id = crypto.randomUUID();
    const apiKey = crypto.randomUUID();
    const salt = crypto.randomBytes(16).toString('hex');
    const createdAt = new Date().toISOString();
    const entry = {
        id,
        label: normalizedLabel,
        createdAt,
        salt,
        hash: deriveHash(apiKey, salt),
        revokedAt: null,
        lastUsedAt: null,
        secretPreview: apiKey.slice(0, 8),
        disabled: false
    };
    store.keys.push(entry);
    await saveStore(store);
    return {
        id,
        label: normalizedLabel,
        apiKey,
        createdAt
    };
}

async function revokeKey(id) {
    const store = await loadStore();
    const entry = store.keys.find((key) => key.id === id);
    if (!entry) {
        return false;
    }
    if (!entry.revokedAt) {
        entry.revokedAt = new Date().toISOString();
    }
    await saveStore(store);
    return true;
}

async function removeKey(id, label) {
    const store = await loadStore();
    const index = store.keys.findIndex((key) => key.id === id);
    if (index === -1) {
        return false;
    }
    const provided = (label || '').trim();
    const expected = (store.keys[index].label || '').trim();
    if (!provided) {
        const error = new Error('Label required');
        error.code = 'LABEL_REQUIRED';
        throw error;
    }
    if (provided !== expected) {
        const error = new Error('Label mismatch');
        error.code = 'LABEL_MISMATCH';
        throw error;
    }
    store.keys.splice(index, 1);
    await saveStore(store);
    return true;
}

async function verifyKey(apiKey) {
    if (!apiKey || typeof apiKey !== 'string') {
        return { valid: false };
    }
    const store = await loadStore();
    for (const entry of store.keys) {
        if (entry.revokedAt || entry.disabled) {
            continue;
        }
        const computed = deriveHash(apiKey, entry.salt);
        const match = crypto.timingSafeEqual(Buffer.from(computed, 'hex'), Buffer.from(entry.hash, 'hex'));
        if (match) {
            entry.lastUsedAt = new Date().toISOString();
            await saveStore(store);
            return {
                valid: true,
                id: entry.id,
                label: entry.label,
                preview: entry.secretPreview || apiKey.slice(0, 8)
            };
        }
    }
    return { valid: false };
}

async function setDisabled(id, disabled) {
    const store = await loadStore();
    const entry = store.keys.find((key) => key.id === id);
    if (!entry) {
        return null;
    }
    entry.disabled = Boolean(disabled);
    await saveStore(store);
    return sanitizeKey(entry);
}

module.exports = {
    listKeys,
    createKey,
    revokeKey,
    removeKey,
    setDisabled,
    verifyKey
};

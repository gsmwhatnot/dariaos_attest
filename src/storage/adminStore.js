const crypto = require('crypto');
const path = require('path');
const { DATA_DIR, DEFAULT_ADMIN_PASSWORD } = require('../config');
const { readJsonFile, writeJsonFileAtomic } = require('./file');

const ADMIN_FILE = path.join(DATA_DIR, 'admin.json');

function hashPassword(password, salt) {
    return crypto.pbkdf2Sync(password, salt, 120000, 64, 'sha512').toString('hex');
}

async function loadRecord() {
    return readJsonFile(ADMIN_FILE, null);
}

async function saveRecord(record) {
    await writeJsonFileAtomic(ADMIN_FILE, record);
}

async function ensureAdminAccount() {
    const existing = await loadRecord();
    if (existing) {
        return existing;
    }
    const salt = crypto.randomBytes(16).toString('hex');
    const now = new Date().toISOString();
    const record = {
        salt,
        passwordHash: hashPassword(DEFAULT_ADMIN_PASSWORD, salt),
        mustChangePassword: true,
        createdAt: now,
        updatedAt: now
    };
    await saveRecord(record);
    return record;
}

async function verifyAdminPassword(password) {
    const record = await ensureAdminAccount();
    const candidate = hashPassword(password, record.salt);
    const match = crypto.timingSafeEqual(Buffer.from(candidate, 'hex'), Buffer.from(record.passwordHash, 'hex'));
    return {
        success: match,
        mustChangePassword: record.mustChangePassword
    };
}

async function updateAdminPassword(newPassword) {
    const record = await ensureAdminAccount();
    const salt = crypto.randomBytes(16).toString('hex');
    const now = new Date().toISOString();
    const nextRecord = {
        ...record,
        salt,
        passwordHash: hashPassword(newPassword, salt),
        mustChangePassword: false,
        updatedAt: now
    };
    await saveRecord(nextRecord);
    return {
        mustChangePassword: false,
        updatedAt: now
    };
}

async function getAdminState() {
    const record = await ensureAdminAccount();
    const { passwordHash, salt, ...rest } = record;
    return rest;
}

module.exports = {
    ensureAdminAccount,
    verifyAdminPassword,
    updateAdminPassword,
    getAdminState
};

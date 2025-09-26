const crypto = require('crypto');
const { SESSION_SECRET } = require('../config');

const SESSION_TTL_MS = 60 * 60 * 1000; // 1 hour
const SECRET = SESSION_SECRET || 'change-me-session-secret';

const sessions = new Map(); // tokenHash -> entry

function hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
}

function pruneExpired() {
    const now = Date.now();
    for (const [key, entry] of sessions.entries()) {
        const expiresAt = entry.expiresAt ? new Date(entry.expiresAt).getTime() : null;
        if (expiresAt && expiresAt <= now) {
            sessions.delete(key);
        }
    }
}

function signPayload(encodedPayload) {
    return crypto.createHmac('sha256', SECRET).update(encodedPayload).digest('base64url');
}

function encodePayload(payload) {
    return Buffer.from(JSON.stringify(payload)).toString('base64url');
}

function decodePayload(encoded) {
    try {
        const json = Buffer.from(encoded, 'base64url').toString('utf8');
        return JSON.parse(json);
    } catch (error) {
        return null;
    }
}

function createSession() {
    pruneExpired();
    const id = crypto.randomBytes(16).toString('hex');
    const now = new Date();
    const expiresAt = new Date(now.getTime() + SESSION_TTL_MS).toISOString();
    const payload = { id, exp: expiresAt };
    const encodedPayload = encodePayload(payload);
    const signature = signPayload(encodedPayload);
    const token = `${encodedPayload}.${signature}`;
    const tokenHash = hashToken(token);

    sessions.set(tokenHash, {
        createdAt: now.toISOString(),
        lastSeenAt: now.toISOString(),
        expiresAt
    });

    return {
        token,
        expiresAt
    };
}

function validateSession(token) {
    if (!token) {
        return null;
    }
    pruneExpired();
    const [encodedPayload, signature] = token.split('.');
    if (!encodedPayload || !signature) {
        return null;
    }
    const expectedSignature = signPayload(encodedPayload);
    const providedBuf = Buffer.from(signature, 'utf8');
    const expectedBuf = Buffer.from(expectedSignature, 'utf8');
    if (providedBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(providedBuf, expectedBuf)) {
        return null;
    }
    const payload = decodePayload(encodedPayload);
    if (!payload || !payload.id || !payload.exp) {
        return null;
    }
    const expiresAtMs = Date.parse(payload.exp);
    if (Number.isNaN(expiresAtMs) || expiresAtMs <= Date.now()) {
        return null;
    }
    const tokenHash = hashToken(token);
    const entry = sessions.get(tokenHash);
    if (!entry) {
        return null;
    }
    entry.lastSeenAt = new Date().toISOString();
    return {
        token,
        expiresAt: entry.expiresAt
    };
}

function revokeSession(token) {
    if (!token) {
        return false;
    }
    const tokenHash = hashToken(token);
    return sessions.delete(tokenHash);
}

module.exports = {
    createSession,
    validateSession,
    revokeSession
};

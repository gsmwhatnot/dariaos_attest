const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '..', '..');
const DATA_DIR = path.join(ROOT_DIR, 'data');
const LOGS_DIR = path.join(ROOT_DIR, 'logs');

const SITE_NAME = process.env.SITE_NAME || 'Daria Attestation Service';

const parsedPort = parseInt(process.env.PORT || '8080', 10);
const PORT = Number.isNaN(parsedPort) ? 8080 : parsedPort;

const DEFAULT_ADMIN_PASSWORD = process.env.DEFAULT_ADMIN_PASSWORD || 'admin';

const rawBaseUrl = process.env.BASE_URL || '';

function parseBaseUrl(rawUrl) {
    if (!rawUrl) {
        return {
            origin: '',
            basePath: '',
            toAppPath(relativePath = '') {
                const safe = relativePath.startsWith('/') ? relativePath : `/${relativePath}`;
                const combined = safe.replace(/\/{2,}/g, '/');
                const trimmed = combined.endsWith('/') && combined !== '/' ? combined.slice(0, -1) : combined;
                return trimmed === '' ? '/' : trimmed;
            }
        };
    }

    const url = new URL(rawUrl);
    const pathname = url.pathname.replace(/\/+$/u, '');
    const basePath = pathname === '' ? '' : pathname;

    return {
        origin: `${url.protocol}//${url.host}`,
        basePath,
        toAppPath(relativePath = '') {
            const safe = relativePath.startsWith('/') ? relativePath : `/${relativePath}`;
            const combined = `${basePath}${safe}`.replace(/\/{2,}/g, '/');
            const trimmed = combined.endsWith('/') && combined !== '/' ? combined.slice(0, -1) : combined;
            return trimmed === '' ? '/' : trimmed;
        }
    };
}

const baseUrlInfo = rawBaseUrl ? parseBaseUrl(rawBaseUrl) : parseBaseUrl('');

const ATTESTATION_TIMEOUT_SECONDS = (() => {
    const raw = parseInt(process.env.ATTESTATION_TIMEOUT || '600', 10);
    if (Number.isNaN(raw) || raw < 0) {
        return 600;
    }
    return raw;
})();

const ATTESTATION_TIMEOUT_MS = ATTESTATION_TIMEOUT_SECONDS * 1000;

const GOOGLE_ROOTS_URL = process.env.GOOGLE_ATTESTATION_ROOTS_URL || 'https://android.googleapis.com/attestation/root';
const GOOGLE_STATUS_URL = process.env.GOOGLE_ATTESTATION_STATUS_URL || 'https://android.googleapis.com/attestation/status';
const ROOT_REFRESH_INTERVAL_MS = 6 * 60 * 60 * 1000; // 6 hours

const SESSION_SECRET = process.env.SESSION_SECRET || 'change-me-session-secret';

const ENFORCE_REMOTE_KEY_PROVISION = (() => {
    const raw = (process.env.ENFORCE_REMOTE_KEY_PROVISION || 'FALSE').toString().trim().toLowerCase();
    if (['1', 'true', 'yes', 'on'].includes(raw)) {
        return true;
    }
    return false;
})();

const ENFORCE_API_KEY = (() => {
    const raw = (process.env.ENFORCE_API_KEY || 'FALSE').toString().trim().toLowerCase();
    if (['1', 'true', 'yes', 'on'].includes(raw)) {
        return true;
    }
    return false;
})();

module.exports = {
    SITE_NAME,
    PORT,
    DEFAULT_ADMIN_PASSWORD,
    BASE_ORIGIN: baseUrlInfo.origin,
    BASE_PATH: baseUrlInfo.basePath,
    resolveAppPath: baseUrlInfo.toAppPath,
    ROOT_DIR,
    DATA_DIR,
    LOGS_DIR,
    GOOGLE_ROOTS_URL,
    GOOGLE_STATUS_URL,
    ROOT_REFRESH_INTERVAL_MS,
    ATTESTATION_TIMEOUT_SECONDS,
    ATTESTATION_TIMEOUT_MS,
    SESSION_SECRET,
    ENFORCE_REMOTE_KEY_PROVISION,
    ENFORCE_API_KEY
};

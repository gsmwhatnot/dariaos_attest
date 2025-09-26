function maskApiKey(apiKey) {
    if (!apiKey || typeof apiKey !== 'string') {
        return 'unknown';
    }
    return `${apiKey.slice(0, 8)}...`;
}

function safeString(value) {
    if (value === null || value === undefined) {
        return '';
    }
    return String(value);
}

function bufferToPrintable(buffer) {
    if (!buffer || buffer.length === 0) {
        return '';
    }
    const text = buffer.toString('utf8');
    if (!Buffer.from(text, 'utf8').equals(buffer)) {
        return null;
    }
    if (text.includes('\uFFFD')) {
        return null;
    }
    const stripped = text.replace(/[\r\n\t]/g, '');
    for (let index = 0; index < stripped.length; index += 1) {
        const code = stripped.charCodeAt(index);
        const isControl = code < 0x20 || code === 0x7f;
        if (isControl) {
            return null;
        }
    }
    return text;
}

module.exports = {
    maskApiKey,
    safeString,
    bufferToPrintable
};


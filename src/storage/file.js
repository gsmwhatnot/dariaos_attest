const fs = require('fs/promises');
const path = require('path');

async function ensureDir(dirPath) {
    await fs.mkdir(dirPath, { recursive: true });
}

async function readJsonFile(filePath, defaultValue = null) {
    try {
        const buffer = await fs.readFile(filePath, 'utf8');
        return JSON.parse(buffer);
    } catch (error) {
        if (error.code === 'ENOENT') {
            return defaultValue;
        }
        throw error;
    }
}

async function writeJsonFileAtomic(filePath, data, options = {}) {
    const dir = path.dirname(filePath);
    await ensureDir(dir);
    const tmpPath = `${filePath}.${Date.now()}.tmp`;
    const space = Number.isInteger(options.space) ? options.space : 2;
    const payload = JSON.stringify(data, null, space);
    await fs.writeFile(tmpPath, payload, 'utf8');
    await fs.rename(tmpPath, filePath);
}

async function writeTextFileAtomic(filePath, contents) {
    const dir = path.dirname(filePath);
    await ensureDir(dir);
    const tmpPath = `${filePath}.${Date.now()}.tmp`;
    await fs.writeFile(tmpPath, contents, 'utf8');
    await fs.rename(tmpPath, filePath);
}

async function appendJsonl(filePath, entry) {
    const dir = path.dirname(filePath);
    await ensureDir(dir);
    const line = `${JSON.stringify(entry)}\n`;
    await fs.appendFile(filePath, line, 'utf8');
}

module.exports = {
    ensureDir,
    readJsonFile,
    writeJsonFileAtomic,
    writeTextFileAtomic,
    appendJsonl
};

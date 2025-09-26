const fs = require('fs/promises');
const { writeJsonFileAtomic } = require('./file');

function sanitizeRecord(record) {
    if (!record || !record.serial) {
        return null;
    }
    const nowIso = new Date().toISOString();
    return {
        model: record.model || '',
        serial: record.serial,
        createdAt: record.createdAt || record.updatedAt || nowIso,
        updatedAt: record.updatedAt || record.createdAt || nowIso,
        keyDescription: record.keyDescription ?? null
    };
}

function ledgerFromRecords(records) {
    const devices = [];
    for (const record of records) {
        const clean = sanitizeRecord(record);
        if (!clean) {
            continue;
        }
        const deviceId = `${clean.model}${clean.serial}`;
        devices.push({ device: deviceId, value: [clean] });
    }
    return { devices };
}

function sanitizeLedger(parsed) {
    if (!parsed || !Array.isArray(parsed.devices)) {
        return { devices: [] };
    }
    const records = parsed.devices.map((entry) => {
        const first = Array.isArray(entry?.value) && entry.value.length > 0 ? entry.value[0] : {};
        return {
            model: first.model || '',
            serial: first.serial || (entry?.device || '').replace(first.model || '', ''),
            createdAt: first.createdAt,
            updatedAt: first.updatedAt,
            keyDescription: first.keyDescription
        };
    });
    return ledgerFromRecords(records);
}

async function readDeviceLedger(filePath) {
    try {
        const text = await fs.readFile(filePath, 'utf8');
        const trimmed = text.trim();
        if (!trimmed) {
            return { devices: [] };
        }
        try {
            const parsed = JSON.parse(trimmed);
            if (Array.isArray(parsed.devices)) {
                return sanitizeLedger(parsed);
            }
            if (Array.isArray(parsed)) {
                return ledgerFromRecords(parsed);
            }
            if (typeof parsed === 'object' && parsed !== null) {
                const entries = Object.entries(parsed).map(([serial, value]) => ({
                    model: value?.model || '',
                    serial,
                    createdAt: value?.createdAt,
                    updatedAt: value?.updatedAt,
                    keyDescription: value?.keyDescription ?? null
                }));
                return ledgerFromRecords(entries);
            }
        } catch (jsonError) {
            const lines = trimmed.split(/\r?\n/);
            const records = [];
            for (const line of lines) {
                const candidate = line.trim();
                if (!candidate) {
                    continue;
                }
                try {
                    const parsedLine = JSON.parse(candidate);
                    records.push(parsedLine);
                } catch (lineError) {
                    // skip invalid lines
                }
            }
            return ledgerFromRecords(records);
        }
    } catch (error) {
        if (error.code === 'ENOENT') {
            return { devices: [] };
        }
        throw error;
    }
    return { devices: [] };
}

async function upsertDeviceRecord(filePath, { serial, model, keyDescription }) {
    const ledger = await readDeviceLedger(filePath);
    const deviceId = `${model || ''}${serial}`;
    const nowIso = new Date().toISOString();

    let entry = ledger.devices.find((item) => {
        if (item.device === deviceId) {
            return true;
        }
        const record = Array.isArray(item.value) && item.value.length > 0 ? item.value[0] : null;
        return record?.serial === serial;
    });

    if (!entry) {
        entry = {
            device: deviceId,
            value: [
                {
                    model: model || '',
                    serial,
                    createdAt: nowIso,
                    updatedAt: nowIso,
                    keyDescription
                }
            ]
        };
        ledger.devices.push(entry);
    } else {
        const existing = Array.isArray(entry.value) && entry.value.length > 0 ? entry.value[0] : null;
        const createdAt = existing?.createdAt || nowIso;
        entry.device = deviceId;
        entry.value = [
            {
                model: model || existing?.model || '',
                serial,
                createdAt,
                updatedAt: nowIso,
                keyDescription
            }
        ];
    }

    await writeJsonFileAtomic(filePath, ledger, { space: 2 });
}

module.exports = {
    upsertDeviceRecord
};


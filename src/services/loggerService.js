const { writeAccessLog, writeAuditLog, writeDeviceAttestLog } = require('../storage');

function createLoggerService() {
    async function safeWrite(writer, event) {
        try {
            await writer(event);
        } catch (error) {
            // eslint-disable-next-line no-console
            console.error('Failed to write log entry', error);
        }
    }

    return {
        access: (event) => safeWrite(writeAccessLog, event),
        audit: (event) => safeWrite(writeAuditLog, event),
        deviceAttest: (payload) => safeWrite(writeDeviceAttestLog, payload)
    };
}

module.exports = createLoggerService;

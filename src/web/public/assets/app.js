(function () {
    const TOKEN_STORAGE_KEY = 'dariaAdminToken';

    const state = {
        token: window.localStorage.getItem(TOKEN_STORAGE_KEY) || null,
        mustChangePassword: false,
        siteName: 'dariaAttest',
        sessionExpiresAt: null
    };

    const alertsEl = document.getElementById('alerts');
    const loginSection = document.getElementById('login-section');
    const passwordSection = document.getElementById('password-section');
    const keysSection = document.getElementById('keys-section');
    const newKeySection = document.getElementById('new-key-section');
    const keysTableBody = document.querySelector('#keys-table tbody');
    const newKeyValue = document.getElementById('new-key-value');
    const titleEl = document.getElementById('app-title');
    const modalBackdrop = document.getElementById('modal-backdrop');
    const createKeyForm = document.getElementById('create-key-form');
    const createKeyLabelInput = document.getElementById('create-key-label');
    const createKeyCancel = document.getElementById('create-key-cancel');
    const createKeyError = document.getElementById('create-key-error');
    const createdHeader = document.getElementById('created-header');
    const lastUsedHeader = document.getElementById('last-used-header');

    const alertTimers = new Set();

    const isAuthenticated = () => Boolean(state.token);

    function formatTimezoneOffset() {
        const minutes = -new Date().getTimezoneOffset();
        const sign = minutes >= 0 ? '+' : '-';
        const absolute = Math.abs(minutes);
        const hours = String(Math.floor(absolute / 60)).padStart(2, '0');
        const mins = String(absolute % 60).padStart(2, '0');
        return `${sign}${hours}:${mins}`;
    }

    (function updateTimezoneHeaders() {
        const offsetText = formatTimezoneOffset();
        if (createdHeader) {
            createdHeader.textContent = `Created (${offsetText})`;
        }
        if (lastUsedHeader) {
            lastUsedHeader.textContent = `Last Used (${offsetText})`;
        }
    }());

    function openCreateModal() {
        if (!modalBackdrop.classList.contains('hidden')) {
            return;
        }
        createKeyLabelInput.value = '';
        clearCreateKeyError();
        modalBackdrop.classList.remove('hidden');
        setTimeout(() => createKeyLabelInput.focus(), 0);
    }

    function closeCreateModal() {
        if (modalBackdrop.classList.contains('hidden')) {
            return;
        }
        modalBackdrop.classList.add('hidden');
        createKeyLabelInput.value = '';
        clearCreateKeyError();
    }

    // Ensure modal starts hidden even if refresh occurred mid-dialog
    closeCreateModal();

    document.getElementById('login-form').addEventListener('submit', async (event) => {
        event.preventDefault();
        clearAlerts();
        const password = document.getElementById('login-password').value.trim();
        if (!password) {
            showAlert('error', 'Password required');
            return;
        }
        try {
            const response = await apiFetch('api/login', {
                method: 'POST',
                body: { password },
                withAuth: false
            });
            state.token = response.token;
            state.mustChangePassword = Boolean(response.mustChangePassword);
            state.sessionExpiresAt = response.expiresAt || null;
            window.localStorage.setItem(TOKEN_STORAGE_KEY, state.token);
            showAlert('info', 'Login successful', { duration: 4000 });
            await loadProfile();
        } catch (error) {
            state.token = null;
            window.localStorage.removeItem(TOKEN_STORAGE_KEY);
            updateVisibility();
            showAlert('error', error.message || 'Login failed');
        }
    });

    document.getElementById('password-form').addEventListener('submit', async (event) => {
        event.preventDefault();
        clearAlerts();
        if (!isAuthenticated()) {
            showAlert('error', 'You are not signed in');
            return;
        }
        const currentPassword = document.getElementById('current-password').value;
        const newPassword = document.getElementById('new-password').value;
        if (!newPassword || newPassword.length < 8) {
            showAlert('error', 'New password must be at least 8 characters');
            return;
        }
        try {
            await apiFetch('api/password', {
                method: 'POST',
                body: { currentPassword, newPassword }
            });
            state.mustChangePassword = false;
            document.getElementById('password-form').reset();
            showAlert('info', 'Password updated', { duration: 4000 });
            await loadKeys();
            updateVisibility();
        } catch (error) {
            showAlert('error', error.message || 'Unable to update password');
        }
    });

    document.getElementById('create-key-btn').addEventListener('click', () => {
        if (!isAuthenticated() || state.mustChangePassword) {
            showAlert('error', 'You are not signed in');
            return;
        }
        openCreateModal();
    });

    document.getElementById('close-new-key').addEventListener('click', () => {
        newKeySection.classList.add('hidden');
        newKeyValue.textContent = '';
    });

    document.getElementById('logout-btn').addEventListener('click', async () => {
        if (!isAuthenticated()) {
            return;
        }
        clearAlerts();
        try {
            await apiFetch('api/logout', { method: 'POST' });
        } catch (error) {
            // ignore logout errors so the client still clears session
        }
        state.token = null;
        state.mustChangePassword = false;
        state.sessionExpiresAt = null;
        window.localStorage.removeItem(TOKEN_STORAGE_KEY);
        updateVisibility();
        showAlert('info', 'Signed out', { duration: 4000 });
    });

    createKeyCancel.addEventListener('click', () => {
        closeCreateModal();
    });

    if (createKeyLabelInput) {
        createKeyLabelInput.addEventListener('input', () => {
            clearCreateKeyError();
        });
    }

    modalBackdrop.addEventListener('click', (event) => {
        if (event.target === modalBackdrop) {
            closeCreateModal();
        }
    });

    createKeyForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        if (!isAuthenticated() || state.mustChangePassword) {
            closeCreateModal();
            showAlert('error', 'You are not signed in');
            return;
        }
        clearCreateKeyError();
        const label = (createKeyLabelInput.value || '').trim();
        if (!label) {
            showCreateKeyError('Label is required');
            createKeyLabelInput.focus();
            return;
        }
        clearAlerts();
        try {
            const result = await apiFetch('api/keys', {
                method: 'POST',
                body: { label }
            });
            closeCreateModal();
            newKeyValue.textContent = result.apiKey;
            newKeySection.classList.remove('hidden');
            await loadKeys();
            showAlert('warning', 'API key created. Copy it now, it will not be shown again.', { duration: 10000 });
        } catch (error) {
            if (error.message === 'Label already exists' || error.message === 'Label required') {
                showCreateKeyError(error.message);
                return;
            }
            showAlert('error', error.message || 'Failed to create key');
        }
    });

    newKeyValue.addEventListener('click', async () => {
        const value = (newKeyValue.textContent || '').trim();
        if (!value) {
            return;
        }
        try {
            const copied = await copyText(value);
            if (!copied) {
                throw new Error('Copy failed');
            }
            showAlert('success', 'Copied to clipboard!', { duration: 4000 });
        } catch (error) {
            showAlert('error', 'Unable to copy to clipboard');
        }
    });

    async function loadProfile() {
        if (!isAuthenticated()) {
            updateVisibility();
            return;
        }
        const hadToken = Boolean(state.token);
        try {
            const profile = await apiFetch('api/profile');
            state.mustChangePassword = Boolean(profile.mustChangePassword);
            state.siteName = profile.site || state.siteName;
            state.sessionExpiresAt = profile.session?.expiresAt || null;
            titleEl.textContent = `${state.siteName} Admin`;
            updateVisibility();
            if (!state.mustChangePassword) {
                await loadKeys();
            }
        } catch (error) {
            if (error.message === 'Unauthorized' && hadToken) {
                showAlert('info', 'Session expired. Please sign in again.', { duration: 4000 });
            } else if (error.message && error.message !== 'Unauthorized') {
                showAlert('error', error.message);
            }
            state.token = null;
            state.mustChangePassword = false;
            state.sessionExpiresAt = null;
            window.localStorage.removeItem(TOKEN_STORAGE_KEY);
            updateVisibility();
        }
    }

    async function loadKeys() {
        if (!isAuthenticated() || state.mustChangePassword) {
            return;
        }
        try {
            const data = await apiFetch('api/keys');
            renderKeys(data.keys || []);
        } catch (error) {
            showAlert('error', error.message || 'Failed to load keys');
        }
    }

    function renderKeys(keys) {
        keysTableBody.innerHTML = '';
        if (!keys.length) {
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.colSpan = 6;
            cell.className = 'table-empty';
            cell.textContent = 'No API keys created yet.';
            row.appendChild(cell);
            keysTableBody.appendChild(row);
            return;
        }
        keys.forEach((key) => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${key.label || '(no label)'}</td>
                <td><span class="badge">${key.preview || '????????'}</span></td>
                <td class="status-cell">
                    <button data-toggle-id="${key.id}" type="button" class="toggle-btn ${key.disabled ? 'off' : 'on'}" aria-pressed="${key.disabled}" aria-label="${key.disabled ? 'Enable API key' : 'Disable API key'}">
                        <span></span>
                    </button>
                </td>
                <td>${formatDate(key.createdAt)}</td>
                <td>${formatDate(key.lastUsedAt)}</td>
                <td class="actions">
                    <button data-delete-id="${key.id}" type="button" class="secondary">Delete</button>
                </td>
            `;
            const toggleBtn = row.querySelector('button[data-toggle-id]');
            const deleteBtn = row.querySelector('button[data-delete-id]');

            toggleBtn.setAttribute('title', key.disabled ? 'Enable key' : 'Disable key');
            toggleBtn.setAttribute('aria-label', key.disabled ? 'Enable API key' : 'Disable API key');
            toggleBtn.setAttribute('aria-pressed', key.disabled ? 'true' : 'false');

            toggleBtn.addEventListener('click', async () => {
                const nextState = !key.disabled;
                try {
                    await apiFetch(`api/keys/${key.id}`, {
                        method: 'PATCH',
                        body: { disabled: nextState }
                    });
                    await loadKeys();
                } catch (error) {
                    showAlert('error', error.message || 'Failed to update key');
                }
            });

            deleteBtn.addEventListener('click', async () => {
                const confirmation = window.prompt(`Type the label to delete this API key (case sensitive):`, '');
                if (confirmation === null) {
                    return;
                }
                if (confirmation !== key.label) {
                    showAlert('error', 'Label mismatch. Key not deleted.');
                    return;
                }
                try {
                    await apiFetch(`api/keys/${key.id}`, {
                        method: 'DELETE',
                        body: { label: confirmation }
                    });
                    showAlert('info', 'API key deleted', { duration: 4000 });
                    await loadKeys();
                } catch (error) {
                    showAlert('error', error.message || 'Failed to delete key');
                }
            });
            keysTableBody.appendChild(row);
        });
    }

    function updateVisibility() {
        const authenticated = isAuthenticated();
        loginSection.classList.toggle('hidden', authenticated);
        passwordSection.classList.toggle('hidden', !(authenticated && state.mustChangePassword));
        keysSection.classList.toggle('hidden', !(authenticated && !state.mustChangePassword));
        if (!authenticated) {
            document.getElementById('login-form').reset();
            newKeySection.classList.add('hidden');
            newKeyValue.textContent = '';
        }
        closeCreateModal();
    }

    function showAlert(type, message, options = {}) {
        const variants = {
            error: 'alert-error',
            info: 'alert-info',
            success: 'alert-success',
            warning: 'alert-warning'
        };
        if (!alertsEl) {
            // eslint-disable-next-line no-console
            console.warn('Alert container not available; message:', message);
            return;
        }
        const variantClass = variants[type] || 'alert-info';
        const div = document.createElement('div');
        div.className = `alert ${variantClass}`;
        div.textContent = message;
        alertsEl.classList.remove('hidden');
        alertsEl.appendChild(div);
        if (!options.persist) {
            const timeout = setTimeout(() => {
                if (div.parentNode) {
                    div.parentNode.removeChild(div);
                }
                if (!alertsEl.children.length) {
                    alertsEl.classList.add('hidden');
                }
                alertTimers.delete(timeout);
            }, options.duration || 5000);
            alertTimers.add(timeout);
        }
    }

    function clearAlerts() {
        if (alertsEl) {
            alertsEl.innerHTML = '';
            alertsEl.classList.add('hidden');
        }
        alertTimers.forEach((timeout) => clearTimeout(timeout));
        alertTimers.clear();
    }

    function formatDate(value) {
        if (!value) {
            return '—';
        }
        try {
            return new Date(value).toLocaleString();
        } catch (error) {
            return value;
        }
    }

    async function apiFetch(path, options = {}) {
        const init = {
            method: options.method || 'GET',
            headers: {},
            credentials: 'same-origin'
        };

        if (options.body && init.method !== 'GET') {
            init.headers['Content-Type'] = 'application/json';
            init.body = typeof options.body === 'string' ? options.body : JSON.stringify(options.body);
        }

        if (options.method === 'GET' && options.body) {
            throw new Error('GET requests cannot include a body');
        }

        if (options.withAuth !== false && isAuthenticated()) {
            init.headers.Authorization = `Bearer ${state.token}`;
        }

        const response = await fetch(path, init);
        if (response.status === 401) {
            if (isAuthenticated()) {
                state.token = null;
                state.mustChangePassword = false;
                state.sessionExpiresAt = null;
                window.localStorage.removeItem(TOKEN_STORAGE_KEY);
                updateVisibility();
            }
            throw new Error('Unauthorized');
        }
        if (!response.ok) {
            let message = 'Request failed';
            try {
                const data = await response.json();
                message = data.error || data.reason || message;
            } catch (error) {
                // ignore parse errors
            }
            throw new Error(message);
        }
        if (response.status === 204) {
            return {};
        }
        const text = await response.text();
        return text ? JSON.parse(text) : {};
    }

    async function copyText(text) {
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(text);
            return true;
        }
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.setAttribute('readonly', '');
        textarea.style.position = 'fixed';
        textarea.style.top = '-1000px';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);

        let success = false;
        try {
            textarea.focus();
            textarea.select();
            success = document.execCommand && document.execCommand('copy');
        } catch (error) {
            success = false;
        } finally {
            document.body.removeChild(textarea);
        }
        return success;
    }

    clearAlerts();
    updateVisibility();
    loadProfile();

    function showCreateKeyError(message) {
        if (!createKeyError) {
            showAlert('error', message);
            return;
        }
        createKeyError.textContent = message;
        createKeyError.classList.remove('hidden');
    }

    function clearCreateKeyError() {
        if (!createKeyError) {
            return;
        }
        createKeyError.textContent = '';
        createKeyError.classList.add('hidden');
    }
})();

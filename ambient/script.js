const messageArea = document.getElementById('messageArea');
const createPasskeyButton = document.getElementById('createPasskeyButton');

function showMessage(text, isError = false) {
    if (!messageArea) return;
    messageArea.textContent = text;
    messageArea.className = `mt-6 text-center text-sm min-h-[20px] ${isError ? 'text-red-600 font-semibold' : 'text-gray-600'}`;
}

function generateRandomBuffer(len = 32) {
    if (!window.crypto || !window.crypto.getRandomValues) {
        console.error("Web Crypto API not available.");
        showMessage("Error: Web Crypto API is required for challenge generation.", true);
        return null;
    }
    const randomBytes = new Uint8Array(len);
    window.crypto.getRandomValues(randomBytes);
    return randomBytes;
}

async function createPasskey(currentUsername) {
    if (currentUsername === "") {
        showMessage("Enter a username for the new passkey", true);
        return;
    }

    showMessage("Creating passkey...", false);
    if(createPasskeyButton) createPasskeyButton.disabled = true;

    try {
        const challengeBuffer = generateRandomBuffer();
        if (!challengeBuffer) {
            if(createPasskeyButton) createPasskeyButton.disabled = false;
            return; // Error message shown by generateRandomBuffer
        }

        // ** DEMO ONLY: Encode username into user.id **
        // ** WARNING: Not recommended for production! Use a stable, non-personally-identifiable ID. **
        const userIdBuffer = new TextEncoder().encode(currentUsername);

        const publicKeyCredentialCreationOptions = {
            rp: { name: "Test Page", id: window.location.hostname },
            user: {
                id: userIdBuffer, // Use encoded username as user handle
                name: currentUsername, // Username (for account selection hints)
                displayName: currentUsername, // Display name (for account selection hints)
            },
            challenge: challengeBuffer,
            pubKeyCredParams: [ { type: "public-key", alg: -7 }, { type: "public-key", alg: -257 } ],
            authenticatorSelection: {
                // authenticatorAttachment: "platform", // Optional preference
                userVerification: "preferred",
                residentKey: "required", // Required for discoverable credential (passkey)
            },
            timeout: 60000,
        };

        console.log("Calling navigator.credentials.create with options:", JSON.stringify(publicKeyCredentialCreationOptions, (key, value) => {
            if (value instanceof Uint8Array || value instanceof ArrayBuffer) {
                 // Represent ArrayBuffer as Base64URL for slightly better logging if needed
                 // This is a basic conversion, consider a library for robust handling
                 try {
                     let binary = '';
                     const bytes = new Uint8Array(value);
                     bytes.forEach((byte) => binary += String.fromCharCode(byte));
                     return `[Buffer: ${window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')}]`;
                 } catch (e) {
                     return `[Buffer length=${value.byteLength}]`; // Fallback
                 }
            }
            return value;
        }));

        const newCredential = await navigator.credentials.create({
            publicKey: publicKeyCredentialCreationOptions
        });

        if (newCredential) {
            console.log("New passkey credential created:", newCredential);
            showMessage("Passkey created successfully!", false);
            window.location.href = "welcome.html";
        } else {
            showMessage("Passkey creation failed unexpectedly.", true);
        }

    } catch (error) {
        console.error("navigator.credentials.create error:", error.name, error.message);
        let errorMessage = `Passkey creation failed: ${error.message}`;
        if (error.name === 'NotAllowedError') {
            errorMessage = "Passkey creation cancelled or not allowed.";
        } else if (error.name === 'InvalidStateError') {
             errorMessage = "Passkey creation failed: Invalid state. Perhaps one already exists for this user/device?";
        }
        showPasskeyMessage(errorMessage, true);
    } finally {
         if(createPasskeyButton) createPasskeyButton.disabled = false;
    }
}

function storeInfoAndRedirect(url, username) {
    console.log(`[script.js] Attempting to store info before redirect: username='${username}'`);
    try {
        console.log('[script.js] Clearing sessionStorage...');
        sessionStorage.clear();
        sessionStorage.setItem('username', username);
        console.log('[script.js] Session storage updated. Current values:');
        console.log(`  username: ${sessionStorage.getItem('username')}`);
    } catch (e) {
        console.error("[script.js] Session storage error:", e);
    }
    console.log(`[script.js] Redirecting immediately to ${url}...`);
    window.location.href = url;
}

async function ambientSignIn() {
    const challengeBuffer = generateRandomBuffer();
    let getOptions = {
            publicKey: {
                challenge: challengeBuffer,
                timeout: 300000,
                userVerification: 'preferred',
                rpId: window.location.hostname,
                mediation: 'conditional',
                display: 'ambient',
                allowCredentials: []
            },
            mediation: 'conditional' };

    const credential = await navigator.credentials.get(getOptions);

    if (credential) {
        console.log("[script.js] Credential received:", credential);
        let rawMethod = credential.type;
        let methodToStore = 'Unknown';
        let usernameToStore = "Demo User"; // Default

        if (credential.type !== 'public-key') {
            console.log("[script.js] Unexpected credential type: ", credential.type);
            return;
        }

        if (credential.response && credential.response.userHandle && typeof TextDecoder !== "undefined") {
            try {
                const decodedUsername = new TextDecoder().decode(credential.response.userHandle);
                if (decodedUsername) {
                    usernameToStore = decodedUsername;
                    console.log("[script.js] Decoded username from userHandle:", usernameToStore);
                } else { console.warn("[script.js] UserHandle decoded to empty string."); }
            } catch (decodeError) {
                console.error("[script.js] Failed to decode userHandle:", decodeError);
            }
        } else {
            console.warn("[script.js] UserHandle not found or TextDecoder not supported. Using default username 'Demo User'.");
        }

        storeInfoAndRedirect('site.html', usernameToStore);

    } else {
         console.log("[script.js] navigator.credentials.get returned null.");
         showMessage("Something went wrong with the navigator.credentials.get call :(", true);
    }
}

async function start() {
    console.log("[script.js] Initialization...");

    if (typeof PublicKeyCredential === "undefined") {
        showMessage("WebAuthn not supported by this browser.", 'error');
        return;
    }

    if (typeof TextDecoder === "undefined") {
        console.warn("[script.js] TextDecoder API not supported, cannot read passkey username if encoded in userHandle.");
        return;
    }

    await ambientSignIn();
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
} else {
    start();
}

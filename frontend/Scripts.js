import { Kyber768 } from "crystals-kyber-js";

// ==========================================
// Utilities
// ==========================================

function showToast(message, type = "success") {
    const container = document.getElementById("toastContainer");
    const toast = document.createElement("div");
    toast.className = `toast ${type === 'error' ? 'error' : ''}`;
    toast.innerText = message;
    
    container.appendChild(toast);
    
    // Trigger animation
    requestAnimationFrame(() => {
        toast.classList.add("show");
    });

    setTimeout(() => {
        toast.classList.remove("show");
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

function log(msg) {
    const el = document.getElementById("cryptoLog");
    if (!el) return;
    const div = document.createElement("div");
    div.innerText = `> ${msg}`;
    el.appendChild(div);
    el.scrollTop = el.scrollHeight;
    console.log(msg);
}

function toHex(buffer) {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

function fromHex(hex) {
    return new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

function generateSalt() {
    return window.crypto.getRandomValues(new Uint8Array(16));
}

// ==========================================
// Crypto: AES & PBKDF2
// ==========================================

async function deriveMasterKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

async function encryptAES(key, plaintext) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const ciphertext = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        enc.encode(plaintext)
    );
    
    const combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(ciphertext), iv.length);
    return toHex(combined);
}

async function decryptAES(key, hexData) {
    const data = fromHex(hexData);
    const iv = data.slice(0, 12);
    const ciphertext = data.slice(12);

    try {
        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            ciphertext
        );
        return new TextDecoder().decode(decrypted);
    } catch (e) {
        throw new Error("Decryption failed");
    }
}

// ==========================================
// Application State
// ==========================================
let currentUser = null;
let currentUserSalt = null; // Store salt for verification
let masterKey = null;
let kyberPK = null;
let kyberSK = null;
let isHackerMode = false;

// ==========================================
// UI Logic
// ==========================================

const pages = {
    landing: document.getElementById("landingPage"),
    auth: document.getElementById("authPage"),
    dashboard: document.getElementById("dashboardPage")
};

function showPage(pageName) {
    Object.values(pages).forEach(el => el.classList.add("hidden"));
    pages[pageName].classList.remove("hidden");
    
    // Reset animations
    pages[pageName].classList.remove("animate-slide-up");
    void pages[pageName].offsetWidth; // trigger reflow
    pages[pageName].classList.add("animate-slide-up");
}

// Init
console.log("Crypto Script Loaded");
const startBtn = document.getElementById("startBtn");
if (startBtn) {
    startBtn.disabled = false;
    startBtn.innerHTML = `
        <span class="relative z-10 flex items-center gap-2">
            Launch Vault
            <svg class="w-5 h-5 group-hover:translate-x-1 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7l5 5m0 0l-5 5m5-5H6"></path></svg>
        </span>
    `;
    startBtn.addEventListener("click", () => showPage("auth"));
}

// Toggle Auth Mode
let isRegistering = false;
document.getElementById("toggleAuthMode").addEventListener("click", () => {
    isRegistering = !isRegistering;
    const btn = document.getElementById("authActionBtn");
    const title = document.getElementById("authTitle");
    const toggle = document.getElementById("toggleAuthMode");
    const regFields = document.getElementById("registerFields");

    if (isRegistering) {
        btn.innerText = "Create Quantum Account";
        title.innerText = "Create New Vault";
        toggle.innerText = "Already have an account? Login";
        regFields.classList.remove("hidden");
    } else {
        btn.innerText = "Login";
        title.innerText = "Access Vault";
        toggle.innerText = "New user? Create an account";
        regFields.classList.add("hidden");
    }
});

// Auth Action
document.getElementById("authActionBtn").addEventListener("click", async () => {
    const username = document.getElementById("usernameInput").value;
    const password = document.getElementById("passwordInput").value;
    const btn = document.getElementById("authActionBtn");

    if (!username || !password) return showToast("Please fill all fields", "error");

    btn.disabled = true;
    const originalText = btn.innerText;
    btn.innerText = "Processing...";

    try {
        if (isRegistering) {
            await handleRegister(username, password);
        } else {
            await handleLogin(username, password);
        }
    } finally {
        btn.disabled = false;
        btn.innerText = originalText;
    }
});

// Logout
document.getElementById("logoutBtn").addEventListener("click", () => {
    location.reload();
});

// Add Credential Modal
document.getElementById("addCredBtn").addEventListener("click", () => {
    const modal = document.getElementById("addModal");
    modal.classList.remove("hidden");
    modal.classList.add("flex");
    setTimeout(() => modal.classList.remove("opacity-0"), 10);
});

document.getElementById("cancelAddBtn").addEventListener("click", () => {
    const modal = document.getElementById("addModal");
    modal.classList.add("opacity-0");
    setTimeout(() => {
        modal.classList.add("hidden");
        modal.classList.remove("flex");
    }, 300);
});

document.getElementById("saveCredBtn").addEventListener("click", async () => {
    const site = document.getElementById("newSite").value;
    const user = document.getElementById("newUsername").value;
    const pass = document.getElementById("newPassword").value;
    const notes = document.getElementById("newNotes").value;

    if (!site || !pass) return showToast("Site and Password are required", "error");

    await addCredential(site, user, pass, notes);
    
    document.getElementById("cancelAddBtn").click();
    
    // Clear fields
    document.getElementById("newSite").value = "";
    document.getElementById("newUsername").value = "";
    document.getElementById("newPassword").value = "";
    document.getElementById("newNotes").value = "";
});

// View Modal
document.getElementById("closeViewBtn").addEventListener("click", () => {
    document.getElementById("viewModal").classList.add("hidden");
    document.getElementById("viewModal").classList.remove("flex");
});

// Hacker Mode Toggle
    document.getElementById("attackerToggle").addEventListener("change", (e) => {
        isHackerMode = e.target.checked;
        
        if (isHackerMode) {
            document.body.classList.add("hacker-theme");
            showToast("🕵️‍♂️ HACKER MODE ENABLED: Viewing raw encrypted data");
        } else {
            document.body.classList.remove("hacker-theme");
            // Also close the hacker modal if it's open, to switch back to clean state
            document.getElementById("hackerModal").classList.add("hidden");
            document.getElementById("hackerModal").classList.remove("flex");
        }
        
        loadVault();
    });

document.getElementById("closeHackerBtn").addEventListener("click", () => {
    document.getElementById("hackerModal").classList.add("hidden");
    document.getElementById("hackerModal").classList.remove("flex");
});

// ==========================================
// Core Logic
// ==========================================

async function handleRegister(username, password) {
    try {
        log("Generating Salt...");
        const salt = generateSalt();
        
        log("Deriving Master Key (PBKDF2-SHA256)...");
        masterKey = await deriveMasterKey(password, salt);

        log("Generating Kyber768 Key Pair...");
        const kyber = new Kyber768();
        const [pk, sk] = await kyber.generateKeyPair();
        kyberPK = pk;
        kyberSK = sk;
        log("Kyber Keys Generated.");

        log("Encrypting Private Key...");
        const skHex = toHex(sk);
        const encSK = await encryptAES(masterKey, skHex);

        const payload = {
            username: username,
            salt: toHex(salt),
            enc_sk: encSK,
            pk: toHex(pk)
        };

        const res = await fetch("/api/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        const data = await res.json();
        if (data.status === "success") {
            showToast("Account created! You can now login.");
            isRegistering = false;
            document.getElementById("toggleAuthMode").click();
        } else {
            showToast("Error: " + data.detail, "error");
        }

    } catch (e) {
        console.error(e);
        showToast("Registration failed: " + e.message, "error");
    }
}

async function handleLogin(username, password) {
    try {
        log("Fetching user data...");
        const res = await fetch("/api/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username })
        });

        if (!res.ok) throw new Error("User not found");
        const data = await res.json();

        const salt = fromHex(data.salt);
        currentUserSalt = salt; // Store for later verification
        
        log("Deriving Master Key...");
        masterKey = await deriveMasterKey(password, salt);

        log("Decrypting Kyber Private Key...");
        const skHex = await decryptAES(masterKey, data.enc_sk);
        kyberSK = fromHex(skHex);
        kyberPK = fromHex(data.pk);
        
        currentUser = username;
        log("Login Successful. Keys loaded.");
        
        showDashboard();
        loadVault();

    } catch (e) {
        console.error(e);
        showToast("Login failed. Check credentials.", "error");
    }
}

function showDashboard() {
    showPage("dashboard");
    const userDisplay = document.getElementById("userDisplay");
    userDisplay.querySelector("span").innerText = currentUser;
    userDisplay.classList.remove("hidden");
    userDisplay.classList.add("flex");
    document.getElementById("logoutBtn").classList.remove("hidden");
}

let vaultDataCache = []; // Store loaded data for filtering

async function addCredential(site, username, password, notes) {
    try {
        const category = document.getElementById("newCategory").value;
        log(`Encrypting credential for ${site} (${category})...`);
        
        // Include category in encrypted payload
        const plaintext = JSON.stringify({ site, username, password, notes, category });

        // Kyber Encapsulation
        log("Kyber Encapsulation (Generating Shared Secret)...");
        const kyber = new Kyber768();
        const [ciphertext, sharedSecret] = await kyber.encap(kyberPK);
        
        // Import Shared Secret
        log("Importing Shared Secret as AES Key...");
        const fileKey = await window.crypto.subtle.importKey(
            "raw",
            sharedSecret,
            { name: "AES-GCM" },
            false,
            ["encrypt", "decrypt"]
        );

        // AES Encryption
        log("Encrypting data with Shared Secret...");
        const encryptedContent = await encryptAES(fileKey, plaintext);

        const payload = {
            id: crypto.randomUUID(),
            site: site,
            category: category, // Send plaintext category for filtering (metadata)
            ciphertext: toHex(ciphertext),
            content: encryptedContent
        };

        await fetch(`/api/vault/${currentUser}/add`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        showToast("Credential Encrypted & Stored!");
        loadVault();

    } catch (e) {
        console.error(e);
        showToast("Failed: " + e.message, "error");
    }
}

async function loadVault() {
    const res = await fetch(`/api/vault/${currentUser}`);
    const data = await res.json();
    vaultDataCache = data.vault; // Cache for filtering
    renderVault(vaultDataCache);
}

function renderVault(items) {
    const grid = document.getElementById("vaultGrid");
    grid.innerHTML = "";

    if (items.length === 0) {
        grid.innerHTML = `
            <div class="col-span-full text-center py-10 opacity-50">
                <p class="text-xl mb-2">📭 Vault is Empty</p>
                <p class="text-sm">Add your first quantum-safe credential.</p>
            </div>
        `;
        return;
    }

    items.forEach(item => {
        const card = document.createElement("div");
        
        if (isHackerMode) {
            // HACKER MODE CARD
            card.className = "bg-black p-6 rounded-xl border border-red-600 hover:shadow-[0_0_20px_rgba(220,38,38,0.4)] transition cursor-pointer relative overflow-hidden group";
            card.innerHTML = `
                <div class="absolute inset-0 bg-red-900/10 group-hover:bg-red-900/20 pointer-events-none"></div>
                <div class="flex justify-between items-start relative z-10">
                    <h3 class="font-mono text-lg text-red-500 tracking-widest">ENCRYPTED</h3>
                    <span class="text-[10px] bg-red-900 text-red-200 px-2 py-1 rounded border border-red-500 font-bold">LOCKED</span>
                </div>
                <p class="font-mono text-[10px] text-red-400 mt-4 break-all opacity-70 leading-relaxed">
                    ${item.ciphertext.slice(0, 128)}...
                </p>
                <div class="mt-4 flex gap-2 text-[10px] text-red-300 font-mono border-t border-red-900/50 pt-2">
                   <span>🔒 AES-256</span>
                   <span>⚛ KYBER-768</span>
                </div>
            `;
            card.addEventListener("click", () => openHackerView(item));
        } else {
            // NORMAL MODE CARD
            // Define category colors
            const catColors = {
                "Social": "bg-pink-500/10 text-pink-400 border-pink-500/20",
                "Finance": "bg-green-500/10 text-green-400 border-green-500/20",
                "Work": "bg-blue-500/10 text-blue-400 border-blue-500/20",
                "Personal": "bg-purple-500/10 text-purple-400 border-purple-500/20"
            };
            
            // Default to 'Personal' if category is missing or unknown
            const category = item.category || "Personal";
            const catClass = catColors[category] || catColors["Personal"];

            card.className = "glass-panel p-6 rounded-xl border border-white/5 hover:border-cyan-500/50 hover:shadow-[0_0_20px_rgba(6,182,212,0.15)] transition-all cursor-pointer group hover:-translate-y-1";
            card.innerHTML = `
                <div class="flex justify-between items-start mb-4">
                    <div class="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500/20 to-blue-500/20 flex items-center justify-center text-cyan-400 group-hover:scale-110 transition-transform">
                        <span class="text-lg font-bold">${item.site.charAt(0).toUpperCase()}</span>
                    </div>
                    <div class="flex gap-2">
                        <span class="text-[10px] ${catClass} px-2 py-1 rounded-full border">${category}</span>
                        <span class="text-[10px] bg-cyan-500/10 text-cyan-300 px-2 py-1 rounded-full border border-cyan-500/20">PQC</span>
                    </div>
                </div>
                <h3 class="font-bold text-xl text-white mb-1 group-hover:text-cyan-400 transition-colors">${item.site}</h3>
                <p class="text-xs text-slate-500 font-mono">ID: ${item.id.slice(0, 8)}...</p>
            `;
            card.addEventListener("click", () => openCredential(item));
        }
        
        grid.appendChild(card);
    });
}

// Category Filter Logic
document.getElementById("categoryFilter").addEventListener("change", (e) => {
    const filter = e.target.value;
    if (filter === "all") {
        renderVault(vaultDataCache);
    } else {
        const filtered = vaultDataCache.filter(item => (item.category || "Personal") === filter);
        renderVault(filtered);
    }
});

// Password Strength Meter
document.getElementById("newPassword").addEventListener("input", (e) => {
    const password = e.target.value;
    const bar = document.getElementById("passwordStrengthBar");
    const text = document.getElementById("passwordStrengthText");
    
    let strength = 0;
    if (password.length > 5) strength += 1;
    if (password.length > 10) strength += 1;
    if (/[A-Z]/.test(password)) strength += 1;
    if (/[0-9]/.test(password)) strength += 1;
    if (/[^A-Za-z0-9]/.test(password)) strength += 1;

    let color = "bg-red-500";
    let label = "Weak";
    let width = "20%";

    if (strength >= 4) {
        color = "bg-green-500";
        label = "Strong";
        width = "100%";
    } else if (strength >= 2) {
        color = "bg-yellow-500";
        label = "Medium";
        width = "60%";
    }

    if (password.length === 0) {
        width = "0%";
        label = "None";
    }

    bar.className = `h-full transition-all duration-300 ${color}`;
    bar.style.width = width;
    text.innerText = `Strength: ${label}`;
});

function openHackerView(item) {
    document.getElementById("hackId").innerText = item.id;
    document.getElementById("hackCipher").innerText = item.ciphertext;
    document.getElementById("hackContent").innerText = item.content;
    
    const modal = document.getElementById("hackerModal");
    modal.classList.remove("hidden");
    modal.classList.add("flex");
}

async function openCredential(item) {
    try {
        log(`Decrypting ${item.site}...`);

        // Decapsulate
        const kyber = new Kyber768();
        const sharedSecret = await kyber.decap(fromHex(item.ciphertext), kyberSK);

        // Import Key
        const fileKey = await window.crypto.subtle.importKey(
            "raw",
            sharedSecret,
            { name: "AES-GCM" },
            false,
            ["encrypt", "decrypt"]
        );

        // Decrypt
        log("Decrypting AES content...");
        const jsonStr = await decryptAES(fileKey, item.content);
        const cred = JSON.parse(jsonStr);

        // Show Modal
        document.getElementById("viewSite").innerText = cred.site;
        document.getElementById("viewUsername").innerText = cred.username;
        document.getElementById("viewPassword").innerText = "********";
        
        // Show Notes (Handle empty notes gracefully)
        const notesEl = document.getElementById("viewNotes");
        const notesOverlay = document.getElementById("notesOverlay");
        
        // Reset Overlay
        notesOverlay.classList.remove("hidden");
        
        if (cred.notes && cred.notes.trim() !== "") {
            notesEl.innerText = cred.notes;
            notesEl.classList.remove("italic", "opacity-50");
            
            // Add click listener to overlay
            notesOverlay.onclick = () => {
                // Reuse the verification logic if password isn't already verified
                const passEl = document.getElementById("viewPassword");
                if (passEl.innerText === "********") {
                    // Trigger the password reveal flow
                    document.getElementById("revealBtn").click();
                    showToast("Please verify Master Password to view notes", "info");
                } else {
                    // If password already revealed, just show notes
                    notesOverlay.classList.add("hidden");
                }
            };
        } else {
            notesEl.innerText = "No notes added.";
            notesEl.classList.add("italic", "opacity-50");
            notesOverlay.classList.add("hidden"); // Don't hide empty notes
        }

        document.getElementById("viewKyberInfo").innerText = item.ciphertext.slice(0, 64) + "... [Truncated]";
        
        // Delete Button Logic
        const deleteBtn = document.getElementById("deleteCredBtn");
        // Clone button to remove old listeners
        const newDeleteBtn = deleteBtn.cloneNode(true);
        deleteBtn.parentNode.replaceChild(newDeleteBtn, deleteBtn);
        
        newDeleteBtn.addEventListener("click", async () => {
            if (confirm(`Are you sure you want to delete ${cred.site}? This cannot be undone.`)) {
                try {
                    const res = await fetch(`/api/vault/${currentUser}/delete/${item.id}`, {
                        method: "DELETE"
                    });
                    
                    if (res.ok) {
                        showToast("Credential deleted successfully");
                        document.getElementById("closeViewBtn").click();
                        loadVault(); // Refresh grid
                    } else {
                        throw new Error("Delete failed");
                    }
                } catch (e) {
                    console.error(e);
                    showToast("Failed to delete credential", "error");
                }
            }
        });
        
        // Reset Reveal State
        const revealBtn = document.getElementById("revealBtn");
        const verifySection = document.getElementById("verifySection");
        const verifyInput = document.getElementById("verifyPasswordInput");
        const verifyBtn = document.getElementById("verifyBtn");
        
        revealBtn.classList.remove("hidden");
        verifySection.classList.add("hidden");
        verifyInput.value = "";
        
        revealBtn.onclick = () => {
            const passEl = document.getElementById("viewPassword");
            
            if (passEl.innerText !== "********") {
                // Hide
                passEl.innerText = "********";
                notesOverlay.classList.remove("hidden"); // Re-hide notes
                revealBtn.innerText = "Reveal";
                return;
            }
            
            // Show verification input
            revealBtn.classList.add("hidden");
            verifySection.classList.remove("hidden");
            verifyInput.focus();
        };

        verifyBtn.onclick = async () => {
            const inputPass = verifyInput.value;
            if (!inputPass) return;
            
            verifyBtn.innerText = "Checking...";
            
            try {
                // Verify by deriving key again
                const checkKey = await deriveMasterKey(inputPass, currentUserSalt);
                
                // Export both keys to compare raw bytes
                const rawMaster = await window.crypto.subtle.exportKey("raw", masterKey);
                const rawCheck = await window.crypto.subtle.exportKey("raw", checkKey);
                
                const isMatch = toHex(rawMaster) === toHex(rawCheck);
                
                if (isMatch) {
                    // Reveal BOTH Password and Notes
                    document.getElementById("viewPassword").innerText = cred.password;
                    
                    if (cred.notes && cred.notes.trim() !== "") {
                        notesOverlay.classList.add("hidden");
                    }
                    
                    verifySection.classList.add("hidden");
                    revealBtn.classList.remove("hidden");
                    revealBtn.innerText = "Hide";
                } else {
                    showToast("Incorrect Master Password", "error");
                    verifyInput.value = "";
                }
            } catch (e) {
                console.error(e);
                showToast("Verification Error", "error");
            } finally {import { Kyber768 } from "crystals-kyber-js";

// ==========================================
// Utilities
// ==========================================

function showToast(message, type = "success") {
    const container = document.getElementById("toastContainer");
    const toast = document.createElement("div");
    toast.className = `toast ${type === 'error' ? 'error' : ''}`;
    toast.innerText = message;
    
    container.appendChild(toast);
    
    // Trigger animation
    requestAnimationFrame(() => {
        toast.classList.add("show");
    });

    setTimeout(() => {
        toast.classList.remove("show");
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

function log(msg) {
    const el = document.getElementById("cryptoLog");
    if (!el) return;
    const div = document.createElement("div");
    div.innerText = `> ${msg}`;
    el.appendChild(div);
    el.scrollTop = el.scrollHeight;
    console.log(msg);
}

function toHex(buffer) {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

function fromHex(hex) {
    return new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

function generateSalt() {
    return window.crypto.getRandomValues(new Uint8Array(16));
}

// ==========================================
// Crypto: AES & PBKDF2
// ==========================================

async function deriveMasterKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

async function encryptAES(key, plaintext) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const ciphertext = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        enc.encode(plaintext)
    );
    
    const combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(ciphertext), iv.length);
    return toHex(combined);
}

async function decryptAES(key, hexData) {
    const data = fromHex(hexData);
    const iv = data.slice(0, 12);
    const ciphertext = data.slice(12);

    try {
        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            ciphertext
        );
        return new TextDecoder().decode(decrypted);
    } catch (e) {
        throw new Error("Decryption failed");
    }
}

// ==========================================
// Application State
// ==========================================
let currentUser = null;
let currentUserSalt = null; // Store salt for verification
let masterKey = null;
let kyberPK = null;
let kyberSK = null;
let isHackerMode = false;

// ==========================================
// UI Logic
// ==========================================

const pages = {
    landing: document.getElementById("landingPage"),
    auth: document.getElementById("authPage"),
    dashboard: document.getElementById("dashboardPage")
};

function showPage(pageName) {
    Object.values(pages).forEach(el => el.classList.add("hidden"));
    pages[pageName].classList.remove("hidden");
    
    // Reset animations
    pages[pageName].classList.remove("animate-slide-up");
    void pages[pageName].offsetWidth; // trigger reflow
    pages[pageName].classList.add("animate-slide-up");
}

// Init
console.log("Crypto Script Loaded");
const startBtn = document.getElementById("startBtn");
if (startBtn) {
    startBtn.disabled = false;
    startBtn.innerHTML = `
        <span class="relative z-10 flex items-center gap-2">
            Launch Vault
            <svg class="w-5 h-5 group-hover:translate-x-1 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7l5 5m0 0l-5 5m5-5H6"></path></svg>
        </span>
    `;
    startBtn.addEventListener("click", () => showPage("auth"));
}

// Toggle Auth Mode
let isRegistering = false;
document.getElementById("toggleAuthMode").addEventListener("click", () => {
    isRegistering = !isRegistering;
    const btn = document.getElementById("authActionBtn");
    const title = document.getElementById("authTitle");
    const toggle = document.getElementById("toggleAuthMode");
    const regFields = document.getElementById("registerFields");

    if (isRegistering) {
        btn.innerText = "Create Quantum Account";
        title.innerText = "Create New Vault";
        toggle.innerText = "Already have an account? Login";
        regFields.classList.remove("hidden");
    } else {
        btn.innerText = "Login";
        title.innerText = "Access Vault";
        toggle.innerText = "New user? Create an account";
        regFields.classList.add("hidden");
    }
});

// Auth Action
document.getElementById("authActionBtn").addEventListener("click", async () => {
    const username = document.getElementById("usernameInput").value;
    const password = document.getElementById("passwordInput").value;
    const btn = document.getElementById("authActionBtn");

    if (!username || !password) return showToast("Please fill all fields", "error");

    btn.disabled = true;
    const originalText = btn.innerText;
    btn.innerText = "Processing...";

    try {
        if (isRegistering) {
            await handleRegister(username, password);
        } else {
            await handleLogin(username, password);
        }
    } finally {
        btn.disabled = false;
        btn.innerText = originalText;
    }
});

// Logout
document.getElementById("logoutBtn").addEventListener("click", () => {
    location.reload();
});

// Add Credential Modal
document.getElementById("addCredBtn").addEventListener("click", () => {
    const modal = document.getElementById("addModal");
    modal.classList.remove("hidden");
    modal.classList.add("flex");
    setTimeout(() => modal.classList.remove("opacity-0"), 10);
});

document.getElementById("cancelAddBtn").addEventListener("click", () => {
    const modal = document.getElementById("addModal");
    modal.classList.add("opacity-0");
    setTimeout(() => {
        modal.classList.add("hidden");
        modal.classList.remove("flex");
    }, 300);
});

document.getElementById("saveCredBtn").addEventListener("click", async () => {
    const site = document.getElementById("newSite").value;
    const user = document.getElementById("newUsername").value;
    const pass = document.getElementById("newPassword").value;
    const notes = document.getElementById("newNotes").value;

    if (!site || !pass) return showToast("Site and Password are required", "error");

    await addCredential(site, user, pass, notes);
    
    document.getElementById("cancelAddBtn").click();
    
    // Clear fields
    document.getElementById("newSite").value = "";
    document.getElementById("newUsername").value = "";
    document.getElementById("newPassword").value = "";
    document.getElementById("newNotes").value = "";
});

// View Modal
document.getElementById("closeViewBtn").addEventListener("click", () => {
    document.getElementById("viewModal").classList.add("hidden");
    document.getElementById("viewModal").classList.remove("flex");
});

// Hacker Mode Toggle
    document.getElementById("attackerToggle").addEventListener("change", (e) => {
        isHackerMode = e.target.checked;
        
        if (isHackerMode) {
            document.body.classList.add("hacker-theme");
            showToast("🕵️‍♂️ HACKER MODE ENABLED: Viewing raw encrypted data");
        } else {
            document.body.classList.remove("hacker-theme");
            // Also close the hacker modal if it's open, to switch back to clean state
            document.getElementById("hackerModal").classList.add("hidden");
            document.getElementById("hackerModal").classList.remove("flex");
        }
        
        loadVault();
    });

document.getElementById("closeHackerBtn").addEventListener("click", () => {
    document.getElementById("hackerModal").classList.add("hidden");
    document.getElementById("hackerModal").classList.remove("flex");
});

// ==========================================
// Core Logic
// ==========================================

async function handleRegister(username, password) {
    try {
        log("Generating Salt...");
        const salt = generateSalt();
        
        log("Deriving Master Key (PBKDF2-SHA256)...");
        masterKey = await deriveMasterKey(password, salt);

        log("Generating Kyber768 Key Pair...");
        const kyber = new Kyber768();
        const [pk, sk] = await kyber.generateKeyPair();
        kyberPK = pk;
        kyberSK = sk;
        log("Kyber Keys Generated.");

        log("Encrypting Private Key...");
        const skHex = toHex(sk);
        const encSK = await encryptAES(masterKey, skHex);

        const payload = {
            username: username,
            salt: toHex(salt),
            enc_sk: encSK,
            pk: toHex(pk)
        };

        const res = await fetch("/api/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        const data = await res.json();
        if (data.status === "success") {
            showToast("Account created! You can now login.");
            isRegistering = false;
            document.getElementById("toggleAuthMode").click();
        } else {
            showToast("Error: " + data.detail, "error");
        }

    } catch (e) {
        console.error(e);
        showToast("Registration failed: " + e.message, "error");
    }
}

async function handleLogin(username, password) {
    try {
        log("Fetching user data...");
        const res = await fetch("/api/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username })
        });

        if (!res.ok) throw new Error("User not found");
        const data = await res.json();

        const salt = fromHex(data.salt);
        currentUserSalt = salt; // Store for later verification
        
        log("Deriving Master Key...");
        masterKey = await deriveMasterKey(password, salt);

        log("Decrypting Kyber Private Key...");
        const skHex = await decryptAES(masterKey, data.enc_sk);
        kyberSK = fromHex(skHex);
        kyberPK = fromHex(data.pk);
        
        currentUser = username;
        log("Login Successful. Keys loaded.");
        
        showDashboard();
        loadVault();

    } catch (e) {
        console.error(e);
        showToast("Login failed. Check credentials.", "error");
    }
}

function showDashboard() {
    showPage("dashboard");
    const userDisplay = document.getElementById("userDisplay");
    userDisplay.querySelector("span").innerText = currentUser;
    userDisplay.classList.remove("hidden");
    userDisplay.classList.add("flex");
    document.getElementById("logoutBtn").classList.remove("hidden");
}

let vaultDataCache = []; // Store loaded data for filtering

async function addCredential(site, username, password, notes) {
    try {
        const category = document.getElementById("newCategory").value;
        log(`Encrypting credential for ${site} (${category})...`);
        
        // Include category in encrypted payload
        const plaintext = JSON.stringify({ site, username, password, notes, category });

        // Kyber Encapsulation
        log("Kyber Encapsulation (Generating Shared Secret)...");
        const kyber = new Kyber768();
        const [ciphertext, sharedSecret] = await kyber.encap(kyberPK);
        
        // Import Shared Secret
        log("Importing Shared Secret as AES Key...");
        const fileKey = await window.crypto.subtle.importKey(
            "raw",
            sharedSecret,
            { name: "AES-GCM" },
            false,
            ["encrypt", "decrypt"]
        );

        // AES Encryption
        log("Encrypting data with Shared Secret...");
        const encryptedContent = await encryptAES(fileKey, plaintext);

        const payload = {
            id: crypto.randomUUID(),
            site: site,
            category: category, // Send plaintext category for filtering (metadata)
            ciphertext: toHex(ciphertext),
            content: encryptedContent
        };

        await fetch(`/api/vault/${currentUser}/add`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        showToast("Credential Encrypted & Stored!");
        loadVault();

    } catch (e) {
        console.error(e);
        showToast("Failed: " + e.message, "error");
    }
}

async function loadVault() {
    const res = await fetch(`/api/vault/${currentUser}`);
    const data = await res.json();
    vaultDataCache = data.vault; // Cache for filtering
    renderVault(vaultDataCache);
}

function renderVault(items) {
    const grid = document.getElementById("vaultGrid");
    grid.innerHTML = "";

    if (items.length === 0) {
        grid.innerHTML = `
            <div class="col-span-full text-center py-10 opacity-50">
                <p class="text-xl mb-2">📭 Vault is Empty</p>
                <p class="text-sm">Add your first quantum-safe credential.</p>
            </div>
        `;
        return;
    }

    items.forEach(item => {
        const card = document.createElement("div");
        
        if (isHackerMode) {
            // HACKER MODE CARD
            card.className = "bg-black p-6 rounded-xl border border-red-600 hover:shadow-[0_0_20px_rgba(220,38,38,0.4)] transition cursor-pointer relative overflow-hidden group";
            card.innerHTML = `
                <div class="absolute inset-0 bg-red-900/10 group-hover:bg-red-900/20 pointer-events-none"></div>
                <div class="flex justify-between items-start relative z-10">
                    <h3 class="font-mono text-lg text-red-500 tracking-widest">ENCRYPTED</h3>
                    <span class="text-[10px] bg-red-900 text-red-200 px-2 py-1 rounded border border-red-500 font-bold">LOCKED</span>
                </div>
                <p class="font-mono text-[10px] text-red-400 mt-4 break-all opacity-70 leading-relaxed">
                    ${item.ciphertext.slice(0, 128)}...
                </p>
                <div class="mt-4 flex gap-2 text-[10px] text-red-300 font-mono border-t border-red-900/50 pt-2">
                   <span>🔒 AES-256</span>
                   <span>⚛ KYBER-768</span>
                </div>
            `;
            card.addEventListener("click", () => openHackerView(item));
        } else {
            // NORMAL MODE CARD
            // Define category colors
            const catColors = {
                "Social": "bg-pink-500/10 text-pink-400 border-pink-500/20",
                "Finance": "bg-green-500/10 text-green-400 border-green-500/20",
                "Work": "bg-blue-500/10 text-blue-400 border-blue-500/20",
                "Personal": "bg-purple-500/10 text-purple-400 border-purple-500/20"
            };
            
            // Default to 'Personal' if category is missing or unknown
            const category = item.category || "Personal";
            const catClass = catColors[category] || catColors["Personal"];

            card.className = "glass-panel p-6 rounded-xl border border-white/5 hover:border-cyan-500/50 hover:shadow-[0_0_20px_rgba(6,182,212,0.15)] transition-all cursor-pointer group hover:-translate-y-1";
            card.innerHTML = `
                <div class="flex justify-between items-start mb-4">
                    <div class="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500/20 to-blue-500/20 flex items-center justify-center text-cyan-400 group-hover:scale-110 transition-transform">
                        <span class="text-lg font-bold">${item.site.charAt(0).toUpperCase()}</span>
                    </div>
                    <div class="flex gap-2">
                        <span class="text-[10px] ${catClass} px-2 py-1 rounded-full border">${category}</span>
                        <span class="text-[10px] bg-cyan-500/10 text-cyan-300 px-2 py-1 rounded-full border border-cyan-500/20">PQC</span>
                    </div>
                </div>
                <h3 class="font-bold text-xl text-white mb-1 group-hover:text-cyan-400 transition-colors">${item.site}</h3>
                <p class="text-xs text-slate-500 font-mono">ID: ${item.id.slice(0, 8)}...</p>
            `;
            card.addEventListener("click", () => openCredential(item));
        }
        
        grid.appendChild(card);
    });
}

// Category Filter Logic
document.getElementById("categoryFilter").addEventListener("change", (e) => {
    const filter = e.target.value;
    if (filter === "all") {
        renderVault(vaultDataCache);
    } else {
        const filtered = vaultDataCache.filter(item => (item.category || "Personal") === filter);
        renderVault(filtered);
    }
});

// Password Strength Meter
document.getElementById("newPassword").addEventListener("input", (e) => {
    const password = e.target.value;
    const bar = document.getElementById("passwordStrengthBar");
    const text = document.getElementById("passwordStrengthText");
    
    let strength = 0;
    if (password.length > 5) strength += 1;
    if (password.length > 10) strength += 1;
    if (/[A-Z]/.test(password)) strength += 1;
    if (/[0-9]/.test(password)) strength += 1;
    if (/[^A-Za-z0-9]/.test(password)) strength += 1;

    let color = "bg-red-500";
    let label = "Weak";
    let width = "20%";

    if (strength >= 4) {
        color = "bg-green-500";
        label = "Strong";
        width = "100%";
    } else if (strength >= 2) {
        color = "bg-yellow-500";
        label = "Medium";
        width = "60%";
    }

    if (password.length === 0) {
        width = "0%";
        label = "None";
    }

    bar.className = `h-full transition-all duration-300 ${color}`;
    bar.style.width = width;
    text.innerText = `Strength: ${label}`;
});

function openHackerView(item) {
    document.getElementById("hackId").innerText = item.id;
    document.getElementById("hackCipher").innerText = item.ciphertext;
    document.getElementById("hackContent").innerText = item.content;
    
    const modal = document.getElementById("hackerModal");
    modal.classList.remove("hidden");
    modal.classList.add("flex");
}

async function openCredential(item) {
    try {
        log(`Decrypting ${item.site}...`);

        // Decapsulate
        const kyber = new Kyber768();
        const sharedSecret = await kyber.decap(fromHex(item.ciphertext), kyberSK);

        // Import Key
        const fileKey = await window.crypto.subtle.importKey(
            "raw",
            sharedSecret,
            { name: "AES-GCM" },
            false,
            ["encrypt", "decrypt"]
        );

        // Decrypt
        log("Decrypting AES content...");
        const jsonStr = await decryptAES(fileKey, item.content);
        const cred = JSON.parse(jsonStr);

        // Show Modal
        document.getElementById("viewSite").innerText = cred.site;
        document.getElementById("viewUsername").innerText = cred.username;
        document.getElementById("viewPassword").innerText = "********";
        
        // Show Notes (Handle empty notes gracefully)
        const notesEl = document.getElementById("viewNotes");
        const notesOverlay = document.getElementById("notesOverlay");
        
        // Reset Overlay
        notesOverlay.classList.remove("hidden");
        
        if (cred.notes && cred.notes.trim() !== "") {
            notesEl.innerText = cred.notes;
            notesEl.classList.remove("italic", "opacity-50");
            
            // Add click listener to overlay
            notesOverlay.onclick = () => {
                // Reuse the verification logic if password isn't already verified
                const passEl = document.getElementById("viewPassword");
                if (passEl.innerText === "********") {
                    // Trigger the password reveal flow
                    document.getElementById("revealBtn").click();
                    showToast("Please verify Master Password to view notes", "info");
                } else {
                    // If password already revealed, just show notes
                    notesOverlay.classList.add("hidden");
                }
            };
        } else {
            notesEl.innerText = "No notes added.";
            notesEl.classList.add("italic", "opacity-50");
            notesOverlay.classList.add("hidden"); // Don't hide empty notes
        }

        document.getElementById("viewKyberInfo").innerText = item.ciphertext.slice(0, 64) + "... [Truncated]";
        
        // Delete Button Logic
        const deleteBtn = document.getElementById("deleteCredBtn");
        // Clone button to remove old listeners
        const newDeleteBtn = deleteBtn.cloneNode(true);
        deleteBtn.parentNode.replaceChild(newDeleteBtn, deleteBtn);
        
        newDeleteBtn.addEventListener("click", async () => {
            if (confirm(`Are you sure you want to delete ${cred.site}? This cannot be undone.`)) {
                try {
                    const res = await fetch(`/api/vault/${currentUser}/delete/${item.id}`, {
                        method: "DELETE"
                    });
                    
                    if (res.ok) {
                        showToast("Credential deleted successfully");
                        document.getElementById("closeViewBtn").click();
                        loadVault(); // Refresh grid
                    } else {
                        throw new Error("Delete failed");
                    }
                } catch (e) {
                    console.error(e);
                    showToast("Failed to delete credential", "error");
                }
            }
        });
        
        // Reset Reveal State
        const revealBtn = document.getElementById("revealBtn");
        const verifySection = document.getElementById("verifySection");
        const verifyInput = document.getElementById("verifyPasswordInput");
        const verifyBtn = document.getElementById("verifyBtn");
        
        revealBtn.classList.remove("hidden");
        verifySection.classList.add("hidden");
        verifyInput.value = "";
        
        revealBtn.onclick = () => {
            const passEl = document.getElementById("viewPassword");
            
            if (passEl.innerText !== "********") {
                // Hide
                passEl.innerText = "********";
                notesOverlay.classList.remove("hidden"); // Re-hide notes
                revealBtn.innerText = "Reveal";
                return;
            }
            
            // Show verification input
            revealBtn.classList.add("hidden");
            verifySection.classList.remove("hidden");
            verifyInput.focus();
        };

        verifyBtn.onclick = async () => {
            const inputPass = verifyInput.value;
            if (!inputPass) return;
            
            verifyBtn.innerText = "Checking...";
            
            try {
                // Verify by deriving key again
                const checkKey = await deriveMasterKey(inputPass, currentUserSalt);
                
                // Export both keys to compare raw bytes
                const rawMaster = await window.crypto.subtle.exportKey("raw", masterKey);
                const rawCheck = await window.crypto.subtle.exportKey("raw", checkKey);
                
                const isMatch = toHex(rawMaster) === toHex(rawCheck);
                
                if (isMatch) {
                    // Reveal BOTH Password and Notes
                    document.getElementById("viewPassword").innerText = cred.password;
                    
                    if (cred.notes && cred.notes.trim() !== "") {
                        notesOverlay.classList.add("hidden");
                    }
                    
                    verifySection.classList.add("hidden");
                    revealBtn.classList.remove("hidden");
                    revealBtn.innerText = "Hide";
                } else {
                    showToast("Incorrect Master Password", "error");
                    verifyInput.value = "";
                }
            } catch (e) {
                console.error(e);
                showToast("Verification Error", "error");
            } finally {
                verifyBtn.innerText = "Confirm";
            }
        };

        const modal = document.getElementById("viewModal");
        modal.classList.remove("hidden");
        modal.classList.add("flex");

    } catch (e) {
        console.error(e);
        showToast("Decryption Failed! Integrity check failed.", "error");
    }
}

            }
        };

        const modal = document.getElementById("viewModal");
        modal.classList.remove("hidden");
        modal.classList.add("flex");

    } catch (e) {
        console.error(e);
        showToast("Decryption Failed! Integrity check failed.", "error");
    }
}

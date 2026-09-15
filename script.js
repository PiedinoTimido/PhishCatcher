let geminiKey = '';
let vtKey = '';

const saveBtn = document.getElementById('save-keys-btn');
const deleteBtn = document.getElementById('delete-keys-btn');
const statusMsg = document.getElementById('keys-status');

// Gestisce l'abilitazione/disabilitazione dei pulsanti
function updateKeysUI(isSaved) {
    if (isSaved) {
        saveBtn.disabled = true;
        saveBtn.style.opacity = '0.5';
        saveBtn.style.cursor = 'not-allowed';
        
        deleteBtn.disabled = false;
        deleteBtn.style.opacity = '1';
        deleteBtn.style.cursor = 'pointer';
    } else {
        saveBtn.disabled = false;
        saveBtn.style.opacity = '1';
        saveBtn.style.cursor = 'pointer';
        
        deleteBtn.disabled = true;
        deleteBtn.style.opacity = '0.5';
        deleteBtn.style.cursor = 'not-allowed';
    }
}

// 1. Ripristina le chiavi dal localStorage al caricamento della pagina
document.addEventListener('DOMContentLoaded', () => {
    const savedGemini = localStorage.getItem('phish_gemini_key');
    const savedVt = localStorage.getItem('phish_vt_key');

    if (savedGemini) {
        geminiKey = savedGemini;
        document.getElementById('gemini-api').value = savedGemini;
    }
    if (savedVt) {
        vtKey = savedVt;
        document.getElementById('vt-api').value = savedVt;
    }

    if (savedGemini || savedVt) {
        if (statusMsg) {
            statusMsg.style.color = 'var(--success)';
            statusMsg.textContent = 'API Keys loaded from storage!';
        }
        updateKeysUI(true);
    } else {
        updateKeysUI(false);
    }
});

// 2. Salva le API Keys
document.getElementById('setup-form').addEventListener('submit', (e) => {
    e.preventDefault();
    geminiKey = document.getElementById('gemini-api').value.trim();
    vtKey = document.getElementById('vt-api').value.trim();

    localStorage.setItem('phish_gemini_key', geminiKey);
    localStorage.setItem('phish_vt_key', vtKey);

    if (statusMsg) {
        statusMsg.style.color = 'var(--success)';
        statusMsg.textContent = 'API Keys saved successfully!';
    }
    updateKeysUI(true);
});

// 3. Elimina le API Keys
deleteBtn.addEventListener('click', () => {
    localStorage.removeItem('phish_gemini_key');
    localStorage.removeItem('phish_vt_key');
    geminiKey = '';
    vtKey = '';

    document.getElementById('gemini-api').value = '';
    document.getElementById('vt-api').value = '';

    if (statusMsg) {
        statusMsg.style.color = 'var(--danger)';
        statusMsg.textContent = 'API Keys deleted!';
    }
    updateKeysUI(false);
});

// 4. Gestione Analisi Email
document.getElementById('email-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    if (!geminiKey) {
        alert('Please enter and save a Gemini API key first!');
        return;
    }

    const sender = document.getElementById('sender-email').value;
    const subject = document.getElementById('email-subject').value;
    const body = document.getElementById('email-body').value;

    const resultsSection = document.getElementById('results-section');
    const verdictBadge = document.getElementById('verdict-badge');
    const aiOutput = document.getElementById('ai-output');
    const vtOutput = document.getElementById('vt-output');

    resultsSection.classList.remove('hidden');
    verdictBadge.className = 'badge';
    verdictBadge.textContent = 'Analyzing...';
    aiOutput.textContent = 'Analyzing text patterns with Gemini AI...';
    vtOutput.textContent = 'Scanning for embedded URLs...';

    // A. Analisi Phishing con Gemini API
    try {
        const aiResponse = await analyzeWithGemini(sender, subject, body);
        aiOutput.innerHTML = aiResponse.explanation.replace(/\n/g, '<br>');

        if (aiResponse.isPhishing) {
            verdictBadge.textContent = '⚠️ PHISHING DETECTED';
            verdictBadge.classList.add('danger');
        } else {
            verdictBadge.textContent = '✅ LEGITIMATE EMAIL';
            verdictBadge.classList.add('safe');
        }
    } catch (err) {
        aiOutput.textContent = 'Error connecting to Gemini API: ' + err.message;
        verdictBadge.textContent = 'ERROR';
        verdictBadge.classList.add('warning');
    }

    // B. Estrazione Link e Scansione VirusTotal (se la chiave è presente)
    const extractedUrls = extractUrls(body);

    if (extractedUrls.length === 0) {
        vtOutput.textContent = 'No external URLs found in the email body.';
    } else if (!vtKey) {
        vtOutput.textContent = `Found ${extractedUrls.length} URL(s) (${extractedUrls.join(', ')}). Add a VirusTotal API key to scan them!`;
    } else {
        vtOutput.textContent = `Scanning ${extractedUrls.length} URL(s) on VirusTotal...`;
        try {
            const vtResult = await scanUrlVirusTotal(extractedUrls[0]);
            vtOutput.innerHTML = vtResult;
        } catch (err) {
            vtOutput.textContent = 'VirusTotal Scan Error (CORS or Invalid Key): ' + err.message;
        }
    }
});

// Funzione: Chiamata API a Gemini con gestione errori
async function analyzeWithGemini(sender, subject, body) {
    const prompt = `Act as a SOC Cybersecurity Analyst. Analyze this email for Phishing:
    Sender: ${sender}
    Subject: ${subject}
    Body: ${body}

    Return ONLY a raw JSON object (without markdown code blocks, no \`\`\`json) in this exact format:
    {
    "isPhishing": true,
    "explanation": "Brief explanation of suspicious indicators."
    }`;

    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${geminiKey}`;
    
    const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            contents: [{ parts: [{ text: prompt }] }]
        })
    });

    const data = await response.json();

    if (data.error) {
        throw new Error(`API Error ${data.error.code}: ${data.error.message}`);
    }

    if (!data.candidates || data.candidates.length === 0) {
        throw new Error('No response candidates returned by Gemini. Check prompt or safety settings.');
    }

    const rawText = data.candidates[0].content.parts[0].text;
    const cleanJson = rawText.replace(/```json/g, '').replace(/```/g, '').trim();
    return JSON.parse(cleanJson);
}

// Funzione: Estrazione Regex dei link
function extractUrls(text) {
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    return text.match(urlRegex) || [];
}

// Funzione: Chiamata API a VirusTotal (URL Lookup)
async function scanUrlVirusTotal(targetUrl) {
    const urlId = btoa(targetUrl).replace(/=/g, '');
    const apiUrl = `https://www.virustotal.com/api/v3/urls/${urlId}`;

    const response = await fetch(apiUrl, {
        method: 'GET',
        headers: {
            'x-apikey': vtKey
        }
    });

    if (!response.ok) throw new Error(`HTTP Error ${response.status}`);

    const data = await response.json();
    const stats = data.data.attributes.last_analysis_stats;

    return `<strong>URL:</strong> ${targetUrl}<br>
            <strong>Malicious:</strong> ${stats.malicious} / ${stats.malicious + stats.harmless + stats.undetected}<br>
            <strong>Status:</strong> ${stats.malicious > 0 ? '❌ Dangerous Link' : '✅ Clean Link'}`;
}
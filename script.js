// --- SINGLE URL SCANNER INTERACTION ---
async function checkURL() {
    const urlInput = document.getElementById('urlInput').value;
    const resultContainer = document.getElementById('resultContainer');

    if (!urlInput) {
        alert("Please input a valid target link trajectory first.");
        return;
    }

    resultContainer.classList.remove('hidden');
    resultContainer.innerHTML = `<div style="color:#22d3ee;"><i class="fa-solid fa-spinner fa-spin"></i> Initializing Deep Packet Forensics Engine...</div>`;
    resultContainer.className = ""; 

    try {
        const response = await fetch('http://127.0.0.1:5000/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: urlInput })
        });

        const data = await response.json();
        const f = data.forensics; 

        let uiReport = `
            <div class="verdict-title ${data.result === 'SAFE' ? 'text-safe' : 'text-danger'}" style="margin-bottom: 12px; font-size: 1.1rem;">
                ${data.result === 'SAFE' ? '✅ SYSTEM ASSESSMENT: SECURE DOMAIN' : '⚠️ ALERT: MALICIOUS PHISHING TARGET CONTEXT'}
            </div>
            <div class="forensic-dashboard-grid" style="display:grid; grid-template-columns:1fr 1fr; gap:10px; font-size:0.85rem; text-align:left; color:#94a3b8;">
                <div style="background:rgba(255,255,255,0.03); padding:8px; border-radius:6px;"><strong>URL Character Depth:</strong> ${f.url_length}</div>
                <div style="background:rgba(255,255,255,0.03); padding:8px; border-radius:6px;"><strong>Dot Count Metrics:</strong> ${f.dots}</div>
                <div style="background:rgba(255,255,255,0.03); padding:8px; border-radius:6px;"><strong>Hyphen Segment Counter:</strong> ${f.hyphens}</div>
                <div style="background:rgba(255,255,255,0.03); padding:8px; border-radius:6px;"><strong>Deceptive Keywords Match:</strong> ${f.keyword_triggered}</div>
                <div style="background:rgba(255,255,255,0.03); padding:8px; border-radius:6px;"><strong>Typosquatting Risk Vector:</strong> ${f.typosquatting_detected}</div>
                <div style="background:rgba(255,255,255,0.03); padding:8px; border-radius:6px;"><strong>Closest Legal Brand:</strong> ${f.closest_brand_match} (Diff: ${f.edit_distance})</div>
                <div style="background:rgba(255,255,255,0.03); padding:10px; border-radius:6px; grid-column:span 2; border:1px solid rgba(34,211,238,0.15); color: #fff;">
                    <i class="fa-solid fa-clock" style="color:#22d3ee; margin-right:5px;"></i> 
                    <strong>Infrastructure Domain Age:</strong> ${f.domain_age_days} Days (Registered: ${f.creation_date})
                </div>
            </div>
        `;

        resultContainer.innerHTML = uiReport;
        resultContainer.classList.add(data.result === 'SAFE' ? 'safe' : 'phishing');

    } catch (error) {
        console.error("Connection link offline:", error);
        resultContainer.className = "phishing";
        resultContainer.innerHTML = `<span style="color:#ef4444;">🔴 CRITICAL SYSTEM INTERACTION FAILURE: Check if Flask Server App is active.</span>`;
    }
}

// --- FEATURE C: BULK FILE INGESTION LOGIC ---
let selectedFile = null;

function handleFileSelect(event) {
    selectedFile = event.target.files[0];
    if (selectedFile) {
        document.getElementById('uploadStatusText').innerHTML = `Selected Log File: <span style="color:#22d3ee;font-weight:600;">${selectedFile.name}</span>`;
        document.getElementById('bulkScanBtn').classList.remove('hidden');
    }
}

async function uploadCSVFile(event) {
    if (event && event.preventDefault) event.preventDefault();
    if (event && event.stopPropagation) event.stopPropagation();

    if (!selectedFile) return;

    const bulkResults = document.getElementById('bulkResultContainer');
    
    bulkResults.classList.remove('hidden');
    bulkResults.innerHTML = `<i class="fa-solid fa-spinner fa-spin" style="color:#6366f1;"></i> Ingesting batch pipeline metrics... parsing database log fields...`;

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
        const response = await fetch('http://127.0.0.1:5000/bulk-scan', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (response.ok) {
            // 1. Core Summary Metrics Component Structure Card
            let htmlReport = `
                <div style="color:#10b981; font-weight:700; margin-bottom:12px; letter-spacing:1px;">🚀 BATCH OPERATION REPORT SUCCESSFUL</div>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px; opacity:0.9; border-bottom:1px solid rgba(255,255,255,0.1); padding-bottom:12px; margin-bottom:12px;">
                    <div>• Total Log URLs Analyzed: <strong>${data.total_scanned}</strong></div>
                    <div>• Safe Domains Assessed: <strong style="color:#10b981;">${data.safe_count}</strong></div>
                    <div>• Phishing Attacks Flagged: <strong style="color:#ef4444;">${data.phishing_count}</strong></div>
                </div>
                
                <div style="font-weight:700; font-size:0.8rem; text-transform:uppercase; color:#22d3ee; margin-bottom:8px; display:flex; align-items:center; gap:6px;">
                    <i class="fa-solid fa-list-check"></i> Isolated Target Log Details
                </div>
                <div style="max-height: 180px; overflow-y: auto; display: flex; flex-direction: column; gap: 6px; padding-right: 4px; scrollbar-width: thin;" id="bulkDetailsList">
            `;

            // 2. Loop through every row matching URL tracking parameters dynamically
            if (data.detailed_results && data.detailed_results.length > 0) {
                data.detailed_results.forEach(item => {
                    const isPhish = item.status === "Phishing";
                    htmlReport += `
                        <div style="display:flex; justify-content:space-between; align-items:center; background:rgba(15, 23, 42, 0.4); padding:8px 12px; border-radius:6px; border-left:4px solid ${isPhish ? '#ef4444' : '#10b981'}; font-size:0.8rem;">
                            <span style="color:#e2e8f0; text-overflow:ellipsis; overflow:hidden; white-space:nowrap; max-width:75%; font-family:monospace; text-align:left;">${item.url}</span>
                            <span style="color:${isPhish ? '#ef4444' : '#10b981'}; font-weight:700; font-size:0.75rem; text-transform:uppercase; display:flex; align-items:center; gap:4px;">
                                <i class="fa-solid ${isPhish ? 'fa-triangle-exclamation' : 'fa-circle-check'}"></i> ${item.status}
                            </span>
                        </div>
                    `;
                });
            } else {
                htmlReport += `<div style="color:#94a3b8; font-style:italic; font-size:0.75rem;">No row detail traces parsed.</div>`;
            }

            htmlReport += `</div>`; // Close scrolling list box element
            bulkResults.innerHTML = htmlReport;

        } else {
            bulkResults.innerHTML = `<span style="color:#ef4444;">❌ Batch Error: ${data.error}</span>`;
        }
    } catch (error) {
        console.error("Bulk processing error:", error);
        bulkResults.innerHTML = `<span style="color:#ef4444;">❌ Failed to query enterprise processing route. Ensure Flask is online.</span>`;
    }
}
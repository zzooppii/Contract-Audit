document.addEventListener('DOMContentLoaded', () => {
    // ----------------------------------------------------
    // STATE VARIABLES
    // ----------------------------------------------------
    let currentUser = null;
    let activeAuditId = null;
    let pollingIntervalId = null;
    let activeAuditFindings = [];
    let activeCallGraph = {};
    const auditHistory = new Map(); // audit_id -> audit metadata

    // ----------------------------------------------------
    // DOM ELEMENTS
    // ----------------------------------------------------
    const loginView = document.getElementById('login-view');
    const dashboardView = document.getElementById('dashboard-view');
    const userAvatar = document.getElementById('user-avatar');
    const userName = document.getElementById('user-name');
    
    const auditForm = document.getElementById('audit-form');
    const submitAuditBtn = document.getElementById('submit-audit-btn');
    const submitBtnText = submitAuditBtn.querySelector('.btn-text');
    const submitBtnSpinner = submitAuditBtn.querySelector('.spinner');
    
    const auditHistoryList = document.getElementById('audit-history-list');
    
    // Console / Progress elements
    const progressCard = document.getElementById('progress-card');
    const progressIndicator = document.getElementById('progress-indicator');
    const progressPercentageLabel = document.getElementById('progress-percentage-label');
    const consoleLogOutput = document.getElementById('console-log-output');
    
    const stepInit = document.getElementById('step-init');
    const stepStatic = document.getElementById('step-static');
    const stepDynamic = document.getElementById('step-dynamic');
    const stepEnrich = document.getElementById('step-enrich');

    // Failed Card elements
    const failedCard = document.getElementById('failed-card');
    const failedErrorMsg = document.getElementById('failed-error-msg');

    // Result elements
    const resultCard = document.getElementById('result-card');
    const emptyResultCard = document.getElementById('empty-result-card');
    const resultProjectName = document.getElementById('result-project-name');
    const resultMetaTime = document.getElementById('result-meta-time');
    const reportDownloadsContainer = document.getElementById('report-downloads-container');
    
    const statCritical = document.getElementById('stat-count-critical');
    const statHigh = document.getElementById('stat-count-high');
    const statMedium = document.getElementById('stat-count-medium');
    const statLow = document.getElementById('stat-count-low');
    const findingsAccordionList = document.getElementById('findings-accordion-list');

    // ----------------------------------------------------
    // INITIALIZATION & AUTH CHECKS
    // ----------------------------------------------------
    async function checkAuth() {
        try {
            const response = await fetch('/auth/me');
            if (response.ok) {
                currentUser = await response.json();
                showDashboard();
                loadAuditHistory();
            } else {
                showLogin();
            }
        } catch (error) {
            console.error('Authentication check failed:', error);
            showLogin();
        }
    }

    function showLogin() {
        loginView.classList.add('active');
        dashboardView.classList.remove('active');
    }

    function showDashboard() {
        loginView.classList.remove('active');
        dashboardView.classList.add('active');
        
        // Bind user details
        if (currentUser) {
            userName.textContent = currentUser.name || currentUser.email;
            userAvatar.src = currentUser.picture || 'https://lh3.googleusercontent.com/a/default-user=s96-c';
        }
    }

    // ----------------------------------------------------
    // FORM SUBMISSION & BACKEND AUDIT TRIGGER
    // ----------------------------------------------------
    auditForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        // Reset and clear previous views
        stopPolling();
        clearResultViews();
        
        // Prepare payload
        const formData = new FormData(auditForm);
        const formats = Array.from(formData.getAll('formats'));
        const enableLLM = formData.get('enable_llm') === 'on';
        const projectPath = formData.get('project_path').trim();
        const configPath = formData.get('config_path').trim() || null;

        const payload = {
            project_path: projectPath,
            config_path: configPath,
            enable_llm: enableLLM,
            formats: formats
        };

        // Set Loading state on Button
        setButtonLoading(true);

        try {
            const response = await fetch('/audit/start', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.detail || 'Failed to start audit pipeline');
            }

            const auditStatus = await response.json();
            activeAuditId = auditStatus.audit_id;
            
            // Add to history list tracking immediately
            addOrUpdateHistoryItem({
                id: activeAuditId,
                status: 'pending',
                project_path: projectPath,
                timestamp: new Date().toLocaleTimeString()
            });

            // Trigger poll UI
            showProgressCard();
            startPollingStatus(activeAuditId);

        } catch (error) {
            console.error('Audit submission error:', error);
            showErrorCard(error.message);
            setButtonLoading(false);
        }
    });

    function setButtonLoading(isLoading) {
        if (isLoading) {
            submitAuditBtn.disabled = true;
            submitBtnText.textContent = 'Analyzing Project...';
            submitBtnSpinner.classList.remove('hidden');
        } else {
            submitAuditBtn.disabled = false;
            submitBtnText.textContent = 'Execute Security Audit';
            submitBtnSpinner.classList.add('hidden');
        }
    }

    // ----------------------------------------------------
    // AUDIT STATUS POLLING
    // ----------------------------------------------------
    function startPollingStatus(auditId) {
        // Immediate check
        pollStatus(auditId);
        
        pollingIntervalId = setInterval(() => {
            pollStatus(auditId);
        }, 2000);
    }

    function stopPolling() {
        if (pollingIntervalId) {
            clearInterval(pollingIntervalId);
            pollingIntervalId = null;
        }
    }

    async function pollStatus(auditId) {
        try {
            const response = await fetch(`/audit/${auditId}`);
            if (!response.ok) {
                throw new Error('Audit status retrieval error');
            }

            const statusData = await response.json();
            updateProgressUI(statusData);

            if (statusData.status === 'completed') {
                stopPolling();
                setButtonLoading(false);
                await fetchAndRenderResult(auditId);
                await loadAuditHistory(); // Refresh history listing
            } else if (statusData.status === 'failed') {
                stopPolling();
                setButtonLoading(false);
                showErrorCard(statusData.error || 'Pipeline encountered a failure');
                await loadAuditHistory(); // Refresh history listing
            }
        } catch (error) {
            console.error('Polling status error:', error);
            stopPolling();
            setButtonLoading(false);
            showErrorCard(error.message);
        }
    }

    function updateProgressUI(data) {
        const progress = data.progress || 'Pending...';
        consoleLogOutput.textContent = `[${data.status.toUpperCase()}] ${progress}`;
        
        // Update history status live
        const historyItem = document.querySelector(`[data-id="${data.audit_id}"]`);
        if (historyItem) {
            const badge = historyItem.querySelector('.history-meta');
            if (badge) {
                badge.textContent = `Status: ${data.status}`;
            }
        }

        // Mapping step percentage & active state
        if (progress.includes('Initializing')) {
            setProgressIndicator(15);
            setStepperActive('init');
        } else if (progress.includes('pipeline') || progress.includes('Static')) {
            setProgressIndicator(40);
            setStepperCompleted('init');
            setStepperActive('static');
        } else if (progress.includes('analysis') || progress.includes('Foundry') || progress.includes('fuzz')) {
            setProgressIndicator(65);
            setStepperCompleted('static');
            setStepperActive('dynamic');
        } else if (progress.includes('Enrichment') || progress.includes('LLM') || progress.includes('Remediation')) {
            setProgressIndicator(85);
            setStepperCompleted('dynamic');
            setStepperActive('enrich');
        } else if (data.status === 'completed') {
            setProgressIndicator(100);
            setStepperCompleted('init');
            setStepperCompleted('static');
            setStepperCompleted('dynamic');
            setStepperCompleted('enrich');
        }
    }

    function setProgressIndicator(pct) {
        progressIndicator.style.width = `${pct}%`;
        progressPercentageLabel.textContent = `${pct}%`;
    }

    function setStepperActive(stepId) {
        resetStepperClasses();
        if (stepId === 'init') {
            stepInit.classList.add('active');
        } else if (stepId === 'static') {
            stepInit.classList.add('completed');
            stepStatic.classList.add('active');
        } else if (stepId === 'dynamic') {
            stepInit.classList.add('completed');
            stepStatic.classList.add('completed');
            stepDynamic.classList.add('active');
        } else if (stepId === 'enrich') {
            stepInit.classList.add('completed');
            stepStatic.classList.add('completed');
            stepDynamic.classList.add('completed');
            stepEnrich.classList.add('active');
        }
    }

    function setStepperCompleted(stepId) {
        if (stepId === 'init') stepInit.classList.add('completed');
        if (stepId === 'static') stepStatic.classList.add('completed');
        if (stepId === 'dynamic') stepDynamic.classList.add('completed');
        if (stepId === 'enrich') stepEnrich.classList.add('completed');
    }

    function resetStepperClasses() {
        [stepInit, stepStatic, stepDynamic, stepEnrich].forEach(el => {
            el.classList.remove('active', 'completed');
        });
    }

    // ----------------------------------------------------
    // RENDERING AUDIT RESULTS & SUMMARY
    // ----------------------------------------------------
    async function fetchAndRenderResult(auditId) {
        try {
            const response = await fetch(`/audit/${auditId}/result`);
            if (!response.ok) {
                throw new Error('Could not retrieve audit results');
            }

            const result = await response.json();
            renderResultCard(auditId, result);
        } catch (error) {
            console.error('Fetch result error:', error);
            showErrorCard(error.message);
        }
    }

    function renderResultCard(auditId, result) {
        hideAllRightPanels();
        resultCard.classList.remove('hidden');
        
        // Extract project settings
        const metadata = result.metadata || {};
        const findings = result.findings || [];
        const summary = result.summary || {};
        
        activeAuditFindings = findings;
        activeCallGraph = result.call_graph || {};

        resultProjectName.textContent = `Project: ${metadata.project_name || 'Solidity Project'}`;
        resultMetaTime.textContent = `Analyzed on: ${metadata.timestamp || new Date().toLocaleString()}`;
        
        // Render call graph SVG
        renderCallGraph(activeCallGraph);
        
        // Setup stats counts
        const criticalCount = findings.filter(f => f.severity.toLowerCase() === 'critical').length;
        const highCount = findings.filter(f => f.severity.toLowerCase() === 'high').length;
        const mediumCount = findings.filter(f => f.severity.toLowerCase() === 'medium').length;
        const lowCount = findings.filter(f => f.severity.toLowerCase() === 'low').length;

        statCritical.textContent = criticalCount;
        statHigh.textContent = highCount;
        statMedium.textContent = mediumCount;
        statLow.textContent = lowCount;

        // Render download options
        renderDownloadButtons(auditId, metadata.report_formats || ['sarif', 'json', 'markdown', 'pdf']);

        // Build accordion list
        findingsAccordionList.innerHTML = '';
        if (findings.length === 0) {
            findingsAccordionList.innerHTML = '<div class="empty-state">No vulnerability findings detected. Excellent security posture!</div>';
            return;
        }

        findings.forEach((finding, index) => {
            const item = document.createElement('div');
            item.className = 'accordion-item';
            
            // Format location string
            const locationStr = finding.location 
                ? `${finding.location.filename.split('/').pop()}:${finding.location.line}` 
                : 'Unknown Location';

            const severityClass = finding.severity.toLowerCase();

            item.innerHTML = `
                <div class="accordion-header">
                    <div class="accordion-header-left">
                        <span class="severity-pill ${severityClass}">${finding.severity}</span>
                        <span class="finding-title">${finding.category} - ${finding.detector || 'Custom'}</span>
                    </div>
                    <div class="accordion-header-right">
                        <span class="finding-file">${locationStr}</span>
                        <svg class="chevron-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="6 9 12 15 18 9"/>
                        </svg>
                    </div>
                </div>
                <div class="accordion-content">
                    <div class="accordion-body">
                        <div class="meta-grid">
                            <div class="meta-field">
                                <div class="meta-label">Detector Module</div>
                                <div class="meta-value">${finding.detector}</div>
                            </div>
                            <div class="meta-field">
                                <div class="meta-label">Confidence Rating</div>
                                <div class="meta-value" style="text-transform: capitalize;">${finding.confidence || 'Medium'}</div>
                            </div>
                            <div class="meta-field">
                                <div class="meta-label">Target Location</div>
                                <div class="meta-value">${finding.location ? finding.location.filename : 'N/A'} (Line ${finding.location ? finding.location.line : 'N/A'})</div>
                            </div>
                        </div>

                        <div class="finding-description">
                            <h4>Vulnerability Details</h4>
                            <p>${escapeHtml(finding.description)}</p>
                        </div>

                        ${finding.remediation ? `
                            <div class="finding-remediation">
                                <h4>AI Remediation Recommendation</h4>
                                <p>${escapeHtml(finding.remediation)}</p>
                            </div>
                        ` : ''}

                        ${finding.poc_code ? `
                            <div class="finding-poc">
                                <h4>AI Exploit Proof of Concept (PoC)</h4>
                                <pre><code>${escapeHtml(finding.poc_code)}</code></pre>
                            </div>
                        ` : ''}

                        <button class="btn-code-view" onclick="openCodeDrawerFromFinding(${index})">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px;">
                                <polyline points="16 18 22 12 16 6"/>
                                <polyline points="8 6 2 12 8 18"/>
                            </svg>
                            View Source Code Snippet
                        </button>
                    </div>
                </div>
            `;

            // Toggle expansion
            const header = item.querySelector('.accordion-header');
            header.addEventListener('click', () => {
                item.classList.toggle('open');
            });

            findingsAccordionList.appendChild(item);
        });
    }

    function renderDownloadButtons(auditId, formats) {
        reportDownloadsContainer.innerHTML = '';
        formats.forEach(fmt => {
            const btn = document.createElement('a');
            btn.href = `/reports/${auditId}/${fmt.toLowerCase()}`;
            btn.className = 'btn btn-secondary btn-small';
            btn.setAttribute('download', '');
            btn.innerHTML = `
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px;">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                    <polyline points="7 10 12 15 17 10"/>
                    <line x1="12" y1="15" x2="12" y2="3"/>
                </svg>
                ${fmt.toUpperCase()}
            `;
            reportDownloadsContainer.appendChild(btn);
        });
    }

    // ----------------------------------------------------
    // HISTORY MANAGEMENT
    // ----------------------------------------------------
    async function loadAuditHistory() {
        try {
            const response = await fetch('/audit');
            if (response.ok) {
                const audits = await response.json();
                auditHistoryList.innerHTML = '';
                
                if (audits.length === 0) {
                    auditHistoryList.innerHTML = '<div class="empty-state">No audits recorded yet</div>';
                    return;
                }

                // Show audits in reverse order (newest first)
                audits.reverse().forEach(audit => {
                    addOrUpdateHistoryItem(audit);
                });
            }
        } catch (error) {
            console.error('Load history error:', error);
        }
    }

    function addOrUpdateHistoryItem(audit) {
        // Clear empty state if exists
        const emptyState = auditHistoryList.querySelector('.empty-state');
        if (emptyState) {
            emptyState.remove();
        }

        // Check if item already exists
        let item = auditHistoryList.querySelector(`[data-id="${audit.audit_id}"]`);
        
        if (!item) {
            item = document.createElement('div');
            item.className = 'history-item';
            item.setAttribute('data-id', audit.audit_id);
            auditHistoryList.insertBefore(item, auditHistoryList.firstChild);
        }

        const projectPath = audit.project_path || 'Unknown Project';
        const displayPath = projectPath.split('/').pop() || projectPath;
        const timeStr = audit.timestamp || 'Recent Run';

        item.innerHTML = `
            <div class="history-details">
                <span class="history-path" title="${projectPath}">${displayPath}</span>
                <span class="history-meta">Status: ${audit.status}</span>
            </div>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:16px;height:16px;color:var(--text-muted);">
                <polyline points="9 18 15 12 9 6"/>
            </svg>
        `;

        // Click handler to load the report
        item.onclick = () => {
            // Set active class
            document.querySelectorAll('.history-item').forEach(el => el.classList.remove('active'));
            item.classList.add('active');

            if (audit.status === 'completed') {
                stopPolling();
                fetchAndRenderResult(audit.audit_id);
            } else if (audit.status === 'running') {
                stopPolling();
                showProgressCard();
                startPollingStatus(audit.audit_id);
            } else if (audit.status === 'failed') {
                stopPolling();
                showErrorCard('Audit pipeline failed to finish.');
            }
        };
    }

    // ----------------------------------------------------
    // HELPER UTILITIES
    // ----------------------------------------------------
    function hideAllRightPanels() {
        progressCard.classList.add('hidden');
        failedCard.classList.add('hidden');
        resultCard.classList.add('hidden');
        emptyResultCard.classList.add('hidden');
    }

    function showProgressCard() {
        hideAllRightPanels();
        progressCard.classList.remove('hidden');
        setProgressIndicator(10);
        resetStepperClasses();
        consoleLogOutput.textContent = 'Initializing security pipeline...';
    }

    function showErrorCard(errorMsg) {
        hideAllRightPanels();
        failedCard.classList.remove('hidden');
        failedErrorMsg.textContent = errorMsg;
    }

    function clearResultViews() {
        findingsAccordionList.innerHTML = '';
        statCritical.textContent = '0';
        statHigh.textContent = '0';
        statMedium.textContent = '0';
        statLow.textContent = '0';
    }

    function escapeHtml(string) {
        if (!string) return '';
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return string.replace(/[&<>"']/g, function(m) { return map[m]; });
    }

    // ----------------------------------------------------
    // VISUALIZATION CONTROLLERS & CODE DRAWER
    // ----------------------------------------------------
    window.switchDashboardTab = function(tabName) {
        const btnFindings = document.getElementById('btn-tab-findings');
        const btnCallGraph = document.getElementById('btn-tab-call-graph');
        const tabFindings = document.getElementById('tab-content-findings');
        const tabCallGraph = document.getElementById('tab-content-call-graph');

        if (!btnFindings || !btnCallGraph || !tabFindings || !tabCallGraph) return;

        if (tabName === 'findings') {
            btnFindings.classList.add('active');
            btnCallGraph.classList.remove('active');
            tabFindings.classList.remove('hidden');
            tabFindings.classList.add('active');
            tabCallGraph.classList.add('hidden');
            tabCallGraph.classList.remove('active');
        } else if (tabName === 'call-graph') {
            btnCallGraph.classList.add('active');
            btnFindings.classList.remove('active');
            tabCallGraph.classList.remove('hidden');
            tabCallGraph.classList.add('active');
            tabFindings.classList.add('hidden');
            tabFindings.classList.remove('active');
        }
    };

    window.closeCodeDrawer = function() {
        const drawer = document.getElementById('code-viewer-drawer');
        if (drawer) {
            drawer.classList.add('hidden');
        }
    };

    window.openCodeDrawerFromFinding = function(index) {
        const finding = activeAuditFindings[index];
        if (!finding) return;

        const drawer = document.getElementById('code-viewer-drawer');
        const drawerFilePath = document.getElementById('drawer-file-path');
        const drawerLinesBadge = document.getElementById('drawer-lines-badge');
        const drawerCodeContent = document.getElementById('drawer-code-content');

        const location = finding.location || {};
        const filename = location.filename ? location.filename.split('/').pop() : 'Contract.sol';
        const startLine = location.line || location.start_line || 1;
        const endLine = location.end_line || startLine;

        drawerFilePath.textContent = filename;
        drawerLinesBadge.textContent = `Lines ${startLine} - ${endLine}`;

        let snippet = finding.source_snippet || finding.description || '// Source snippet unavailable';
        
        if (!snippet.includes('\n') && !snippet.startsWith('//')) {
            snippet = `// File: ${filename}\n// Line ${startLine}\nfunction executeVulnerablePattern() public {\n    ${snippet}\n}`;
        }

        drawerCodeContent.textContent = snippet;
        
        if (window.Prism) {
            Prism.highlightElement(drawerCodeContent);
        }

        drawer.classList.remove('hidden');
    };

    function renderCallGraph(callGraphData) {
        const area = document.getElementById('call-graph-render-area');
        if (!area) return;

        if (!callGraphData || Object.keys(callGraphData).length === 0) {
            area.innerHTML = '<div class="empty-state">No cross-contract call topology detected in this project.</div>';
            return;
        }

        let mermaidText = 'graph TD\n';
        const threatContracts = new Set();

        activeAuditFindings.forEach(f => {
            if (f.location && f.location.contract) {
                threatContracts.add(f.location.contract);
            }
            if (f.metadata && f.metadata.vulnerable_contract) {
                threatContracts.add(f.metadata.vulnerable_contract);
            }
        });

        let edgeCount = 0;
        for (const [caller, calls] of Object.entries(callGraphData)) {
            const safeCaller = caller.replace(/[^a-zA-Z0-9_]/g, '_');
            for (const item of calls) {
                const callee = Array.isArray(item) ? item[0] : item;
                const funcName = Array.isArray(item) && item[1] ? item[1] : 'call';
                const safeCallee = callee.replace(/[^a-zA-Z0-9_]/g, '_');

                mermaidText += `    ${safeCaller}["${caller}"] -->|${funcName}| ${safeCallee}["${callee}"]\n`;
                edgeCount++;
            }
        }

        threatContracts.forEach(cname => {
            const safeName = cname.replace(/[^a-zA-Z0-9_]/g, '_');
            mermaidText += `    class ${safeName} threat-node;\n`;
        });

        if (edgeCount === 0) {
            area.innerHTML = '<div class="empty-state">Single contract topology - no cross-contract calls.</div>';
            return;
        }

        area.innerHTML = `<div class="mermaid">${mermaidText}</div>`;

        if (window.mermaid) {
            try {
                mermaid.initialize({ startOnLoad: false, theme: 'dark' });
                mermaid.run({
                    nodes: area.querySelectorAll('.mermaid')
                });
            } catch (err) {
                console.warn('Mermaid render error:', err);
            }
        }
    }

    // Run auth check on initialization
    checkAuth();
});

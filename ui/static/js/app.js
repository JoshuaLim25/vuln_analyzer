// CVE Analyzer Frontend - Minimal & Secure
class HistoryManager {
    constructor(limit = 5) {
        this.STORAGE_KEY = 'cve_analyzer_history';
        this.limit = limit;
    }

    getHistory() {
        try {
            return JSON.parse(localStorage.getItem(this.STORAGE_KEY)) || [];
        } catch (e) {
            return [];
        }
    }

    add(cveId) {
        let history = this.getHistory();
        history = history.filter(item => item !== cveId);
        history.unshift(cveId);
        history = history.slice(0, this.limit);
        localStorage.setItem(this.STORAGE_KEY, JSON.stringify(history));
    }
}

class CVEAnalyzer {
    constructor() {
        this.form = document.getElementById('searchForm');
        this.input = document.getElementById('cveInput');
        this.submitBtn = document.getElementById('submitBtn');
        this.resultContainer = document.getElementById('resultContainer');
        this.userSection = document.getElementById('userSection');
        this.loginSection = document.getElementById('loginSection');
        
        this.historyManager = new HistoryManager();
        this.createHistoryContainer();
        
        this.initEventListeners();
        this.renderHistory();
        this.fetchConfig();
    }
    
    async fetchConfig() {
        try {
            const response = await fetch('/api/config');
            if (response.ok) {
                const config = await response.json();
                
                if (!config.authEnabled) {
                    if (this.userSection) this.userSection.style.display = 'none';
                    if (this.loginSection) this.loginSection.style.display = 'none';
                    return;
                }

                if (config.userEmail) {
                    if (this.userSection) {
                        this.userSection.style.display = 'flex';
                        document.getElementById('userEmail').textContent = config.userEmail;
                    }
                    if (this.loginSection) this.loginSection.style.display = 'none';
                    
                    const tokenStatus = document.getElementById('tokenStatus');
                    if (tokenStatus) {
                        tokenStatus.style.display = config.hasUserToken ? 'inline-block' : 'none';
                    }
                } else {
                    if (this.userSection) this.userSection.style.display = 'none';
                    if (this.loginSection) this.loginSection.style.display = 'block';
                }
            }
        } catch (error) {
            console.error('Failed to fetch config', error);
        }
    }

    createHistoryContainer() {
        const searchSection = document.querySelector('.search-section');
        const historyDiv = document.createElement('div');
        historyDiv.id = 'recentSearches';
        historyDiv.className = 'recent-searches';
        searchSection.appendChild(historyDiv);
        this.recentSearches = historyDiv;
    }
    
    initEventListeners() {
        this.form.addEventListener('submit', (e) => this.handleSubmit(e));
        this.input.addEventListener('input', () => this.validateInput());
        
        this.recentSearches.addEventListener('click', (e) => {
            const historyItem = e.target.closest('.history-item');
            if (historyItem) {
                this.input.value = historyItem.dataset.cve;
                this.validateInput();
                this.handleSubmit(new Event('submit'));
            }
        });
    }
    
    renderHistory() {
        const history = this.historyManager.getHistory();
        if (history.length === 0) {
            this.recentSearches.style.display = 'none';
            return;
        }
        
        this.recentSearches.style.display = 'block';
        this.recentSearches.innerHTML = `
            <span class="history-label">Recent:</span>
            <div class="history-list">
                ${history.map(cve => `<span class="history-item" data-cve="${cve}">${cve}</span>`).join('')}
            </div>
        `;
    }
    
    validateInput() {
        const value = this.input.value.trim();
        const isValid = value.length > 0;
        this.submitBtn.disabled = !isValid;
    }
    
    async handleSubmit(event) {
        if (event) event.preventDefault();
        
        const cveId = this.input.value.trim().toUpperCase();
        if (!cveId) return;
        
        this.setLoading(true);
        this.clearResults();
        
        try {
            const response = await fetch('/api/cve', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ cve: cveId }),
            });
            
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.error || `HTTP ${response.status}`);
            }
            
            const data = await response.json();
            this.historyManager.add(cveId);
            this.renderHistory();
            this.displayResults(cveId, data);
        } catch (error) {
            this.displayError(error.message);
        } finally {
            this.setLoading(false);
        }
    }
    
    setLoading(isLoading) {
        this.submitBtn.disabled = isLoading;
        if (isLoading) {
            this.submitBtn.innerHTML = '<div class="loading-spinner"></div>Analyzing';
        } else {
            this.submitBtn.innerHTML = 'Analyze CVE';
        }
    }
    
    clearResults() {
        this.resultContainer.innerHTML = '';
        this.resultContainer.style.display = 'none';
        this.resultContainer.classList.remove('fade-in');
    }
    
    displayResults(cveId, data) {
        const summaryHtml = this.formatSummary(data.summary);
        const severityClass = (data.severity || 'UNKNOWN').toLowerCase();
        const score = data.score > 0 ? ` (CVSS: ${data.score.toFixed(1)})` : '';

        this.resultContainer.innerHTML = `
            <div class="result-inner">
                <div class="cve-header">
                    <div class="cve-title severity-${severityClass}">${cveId}</div>
                    <div class="cve-meta">
                        <span class="badge badge-${severityClass}">${data.severity || 'UNKNOWN'}${score}</span>
                        <span>Source: ${data.source || 'Unknown'}</span>
                    </div>
                </div>
                <div class="result-content">
                    <div class="summary-content">${summaryHtml}</div>
                </div>
            </div>
        `;
        
        this.resultContainer.style.display = 'block';
    }
    
    displayError(message) {
        this.resultContainer.innerHTML = `
            <div class="result-content error">
                <strong>Error:</strong> ${message}
            </div>
        `;
        this.resultContainer.style.display = 'block';
    }
    
    formatSummary(summary) {
        if (!summary) return 'No summary available.';
        
        let html = summary.replace(/\\u([0-9a-fA-F]{4})/g, (match, grp) => {
            return String.fromCharCode(parseInt(grp, 16));
        });

        html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
        html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>');
        html = html.replace(/^## (.+)$/gm, '<h3>$1</h3>');
        html = html.replace(/^# (.+)$/gm, '<h3>$1</h3>');
        html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
        html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

        let lines = html.split('\n');
        let result = [];
        
        for (let line of lines) {
            line = line.trim();
            if (!line) continue;
            
            if (line.startsWith('<h3>')) {
                result.push(line);
            } else if (line.startsWith('- ') || line.startsWith('* ') || line.startsWith('• ')) {
                const content = line.replace(/^[-*•]\s+/, '');
                result.push(`<p class="list-item">${content}</p>`);
            } else {
                result.push(`<p>${line}</p>`);
            }
        }
        
        return result.join('');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new CVEAnalyzer();
});

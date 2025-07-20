// CVE Analyzer Frontend
class CVEAnalyzer {
    constructor() {
        this.form = document.getElementById('searchForm');
        this.input = document.getElementById('cveInput');
        this.submitBtn = document.getElementById('submitBtn');
        this.resultContainer = document.getElementById('resultContainer');
        
        this.initEventListeners();
    }
    
    initEventListeners() {
        this.form.addEventListener('submit', (e) => this.handleSubmit(e));
        this.input.addEventListener('input', () => this.validateInput());
    }
    
    validateInput() {
        const value = this.input.value.trim();
        const isValid = value.length > 0;
        this.submitBtn.disabled = !isValid;
    }
    
    async handleSubmit(event) {
        event.preventDefault();
        
        const cveId = this.input.value.trim().toUpperCase();
        if (!cveId) return;
        
        this.setLoading(true);
        this.clearResults();
        
        try {
            const response = await fetch('/api/cve', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ cve: cveId }),
            });
            
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.error || `HTTP ${response.status}`);
            }
            
            const data = await response.json();
            this.displayResults(cveId, data);
            
        } catch (error) {
            this.displayError(error.message);
        } finally {
            this.setLoading(false);
        }
    }
    
    setLoading(isLoading) {
        this.submitBtn.disabled = isLoading;
        this.submitBtn.innerHTML = isLoading 
            ? '<div class="spinner"></div> Analyzing...'
            : 'Analyze CVE';
    }
    
    clearResults() {
        this.resultContainer.innerHTML = '';
        this.resultContainer.style.display = 'none';
    }
    
    displayResults(cveId, data) {
        const summaryHtml = this.formatSummary(data.summary);
        
        this.resultContainer.innerHTML = `
            <div class="cve-header">
                <div class="cve-title">${cveId}</div>
                <div class="cve-meta">
                    <span><strong>Source:</strong> ${data.source}</span>
                </div>
            </div>
            <div class="result-content">
                <div class="summary-content">${summaryHtml}</div>
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
        // Convert markdown-like formatting to HTML
        return summary
            .replace(/### (.+)/g, '<h3>$1</h3>')
            .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
            .replace(/\n\n/g, '</p><p>')
            .replace(/^/, '<p>')
            .replace(/$/, '</p>')
            .replace(/<p><h3>/g, '<h3>')
            .replace(/<\/h3><\/p>/g, '</h3>')
            .replace(/<p><\/p>/g, '');
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new CVEAnalyzer();
});
// CVE Analyzer Frontend
class CVEAnalyzer {
    constructor() {
        this.form = document.getElementById('searchForm');
        this.input = document.getElementById('cveInput');
        this.submitBtn = document.getElementById('submitBtn');
        this.resultContainer = document.getElementById('resultContainer');
        this.loadingSpinner = document.getElementById('loadingSpinner');
        
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
        if (isLoading) {
            this.loadingSpinner.classList.add('show');
        } else {
            this.loadingSpinner.classList.remove('show');
        }
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
        let html = summary
            // First handle headers
            .replace(/### (.+)/g, '<h3>$1</h3>')
            // Handle bold text
            .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
            // Handle markdown links - must be before paragraph processing
            .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>')
            // Split into lines and process
            .split('\n');
        
        // Process each line
        let result = [];
        for (let line of html) {
            line = line.trim();
            if (line === '') {
                continue; // Skip empty lines
            } else if (line.startsWith('<h3>')) {
                result.push(line);
            } else if (line.startsWith('- ')) {
                // Handle list items
                result.push('<p>• ' + line.substring(2) + '</p>');
            } else {
                // Regular paragraph
                result.push('<p>' + line + '</p>');
            }
        }
        
        return result.join('');
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new CVEAnalyzer();
});
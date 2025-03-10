// DOM Elements
const lastUpdated = document.getElementById('last-updated');
const totalVulns = document.getElementById('total-vulns');
const criticalVulns = document.getElementById('critical-vulns');
const highVulns = document.getElementById('high-vulns');
const scanStatus = document.getElementById('scan-status');
const scanTarget = document.getElementById('scan-target');
const scanTimestamp = document.getElementById('scan-timestamp');
const vulnTableBody = document.getElementById('vulnerability-table-body');
const refreshBtn = document.querySelector('.refresh-btn');

// Chart
let distributionChart;

// Close flash messages
document.querySelectorAll('.close-btn').forEach(btn => {
    btn.addEventListener('click', function() {
        this.parentElement.remove();
    });
});

// Update timestamp
function updateTimestamp() {
    const now = new Date();
    lastUpdated.textContent = now.toLocaleString();
}

// Fetch vulnerability data
async function fetchVulnerabilities() {
    try {
        const response = await fetch('/api/vulnerabilities');
        const data = await response.json();
        renderVulnerabilityTable(data.results);
        updateSummary(data);
        updateDistributionChart(data.summary);
    } catch (error) {
        console.error('Error fetching vulnerabilities:', error);
    }
}

// Update summary display
function updateSummary(data) {
    totalVulns.textContent = data.total || 0;
    criticalVulns.textContent = data.summary.Critical || 0;
    highVulns.textContent = data.summary.High || 0;
    scanStatus.textContent = data.status || 'None';
    scanTarget.textContent = data.target || 'None';
    scanTimestamp.textContent = data.last_scan || 'None';
    scanStatus.className = '';
    if (data.status === 'Running') {
        scanStatus.classList.add('status-running');
    } else if (data.status === 'Completed') {
        scanStatus.classList.add('status-completed');
    } else if (data.status && data.status.startsWith('Error')) {
        scanStatus.classList.add('status-error');
    }
}

// Render vulnerability table
function renderVulnerabilityTable(vulnerabilities) {
    vulnTableBody.innerHTML = '';
    if (!vulnerabilities || vulnerabilities.length === 0) {
        const row = document.createElement('tr');
        row.innerHTML = '<td colspan="8" class="loading-cell">No vulnerability data available...</td>';
        vulnTableBody.appendChild(row);
        return;
    }
    vulnerabilities.forEach(vuln => {
        const row = document.createElement('tr');
        const severityClass = getSeverityClass(vuln.severity);
        row.innerHTML = `
            <td>${vuln.id || 'N/A'}</td>
            <td>${vuln.name}</td>
            <td>${vuln.host}</td>
            <td>${vuln.port}</td>
            <td><span class="threat-severity ${severityClass}">${vuln.severity}</span></td>
            <td>${vuln.cvss_base}</td>
            <td>${vuln.timestamp}</td>
            <td class="threat-actions">
                <button title="View Details"><i class="fas fa-eye"></i></button>
                <button title="Remediate"><i class="fas fa-wrench"></i></button>
                <button title="Ignore"><i class="fas fa-ban"></i></button>
            </td>
        `;
        vulnTableBody.appendChild(row);
    });
}

function getSeverityClass(severity) {
    switch (severity.toLowerCase()) {
        case 'critical':
            return 'severity-critical';
        case 'high':
            return 'severity-high';
        case 'medium':
            return 'severity-medium';
        case 'low':
            return 'severity-low';
        default:
            return '';
    }
}

function initDistributionChart() {
    const ctx = document.getElementById('vuln-distribution-chart').getContext('2d');
    Chart.defaults.color = '#a9b7d0';
    Chart.defaults.borderColor = '#2a3042';
    distributionChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: ['#ff3b30', '#ff9500', '#ffcc00', '#34c759'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '70%',
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        boxWidth: 12,
                        usePointStyle: true,
                        pointStyle: 'circle'
                    }
                },
                tooltip: {
                    backgroundColor: '#1e2736',
                    titleColor: '#ffffff',
                    bodyColor: '#e0e0e0',
                    borderColor: '#2a3042',
                    borderWidth: 1
                }
            }
        }
    });
}

function updateDistributionChart(summary) {
    if (!distributionChart) return;
    distributionChart.data.datasets[0].data = [
        summary.Critical || 0,
        summary.High || 0,
        summary.Medium || 0,
        summary.Low || 0
    ];
    distributionChart.update();
}

function refreshData() {
    fetchVulnerabilities();
    updateTimestamp();
}

function initDashboard() {
    initDistributionChart();
    refreshData();
    setInterval(refreshData, 30000);
    refreshBtn.addEventListener('click', function() {
        refreshData();
        const refreshIcon = this.querySelector('i');
        refreshIcon.classList.add('fa-spin');
        setTimeout(() => {
            refreshIcon.classList.remove('fa-spin');
        }, 1000);
    });
}

document.addEventListener('DOMContentLoaded', initDashboard);
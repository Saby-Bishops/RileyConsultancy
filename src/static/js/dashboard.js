// DOM Elements
const lastUpdated = document.getElementById('last-updated');
const totalThreats = document.getElementById('total-threats');
const criticalThreats = document.getElementById('critical-threats');
const highThreats = document.getElementById('high-threats');
const blockedThreats = document.getElementById('blocked-threats');
const threatTableBody = document.getElementById('threat-table-body');
const refreshBtn = document.querySelector('.refresh-btn');

// Charts
let trendChart;
let distributionChart;

// Update timestamp
function updateTimestamp() {
    const now = new Date();
    lastUpdated.textContent = now.toLocaleString();
}

// Fetch threats data
async function fetchThreats() {
    try {
        const response = await fetch('/api/threats');
        const threats = await response.json();
        renderThreatTable(threats);
    } catch (error) {
        console.error('Error fetching threats:', error);
    }
}

// Fetch statistics
async function fetchStats() {
    try {
        const response = await fetch('/api/stats');
        const stats = await response.json();
        updateStats(stats);
    } catch (error) {
        console.error('Error fetching stats:', error);
    }
}

// Fetch trend data
async function fetchTrends() {
    try {
        const response = await fetch('/api/trends');
        const trends = await response.json();
        updateTrendChart(trends);
        updateDistributionChart(trends);
    } catch (error) {
        console.error('Error fetching trends:', error);
    }
}

// Update statistics display
function updateStats(stats) {
    totalThreats.textContent = stats.total_threats;
    criticalThreats.textContent = stats.critical;
    highThreats.textContent = stats.high;
    blockedThreats.textContent = stats.blocked;
}

// Render threat table
function renderThreatTable(threats) {
    threatTableBody.innerHTML = '';
    
    threats.forEach(threat => {
        const row = document.createElement('tr');
        
        const severityClass = getSeverityClass(threat.severity);
        
        row.innerHTML = `
            <td>${threat.id}</td>
            <td>${threat.type}</td>
            <td><span class="threat-severity ${severityClass}">${threat.severity}</span></td>
            <td>${threat.source}</td>
            <td>${threat.target}</td>
            <td>${threat.timestamp}</td>
            <td>${threat.details}</td>
            <td class="threat-actions">
                <button title="View Details"><i class="fas fa-eye"></i></button>
                <button title="Investigate"><i class="fas fa-search"></i></button>
                <button title="Block"><i class="fas fa-ban"></i></button>
            </td>
        `;
        
        threatTableBody.appendChild(row);
    });
}

// Get severity class
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

// Initialize trend chart
function initTrendChart() {
    const ctx = document.getElementById('trend-chart').getContext('2d');
    
    // Chart.js global settings for dark theme
    Chart.defaults.color = '#a9b7d0';
    Chart.defaults.borderColor = '#2a3042';
    
    trendChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Malware',
                    data: [],
                    borderColor: '#00b0ff',
                    backgroundColor: 'rgba(0, 176, 255, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Phishing',
                    data: [],
                    borderColor: '#ff9500',
                    backgroundColor: 'rgba(255, 149, 0, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'DDoS',
                    data: [],
                    borderColor: '#ff3b30',
                    backgroundColor: 'rgba(255, 59, 48, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Ransomware',
                    data: [],
                    borderColor: '#5856d6',
                    backgroundColor: 'rgba(88, 86, 214, 0.1)',
                    tension: 0.4,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top',
                    labels: {
                        boxWidth: 12,
                        usePointStyle: true,
                        pointStyle: 'circle'
                    }
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    backgroundColor: '#1e2736',
                    titleColor: '#ffffff',
                    bodyColor: '#e0e0e0',
                    borderColor: '#2a3042',
                    borderWidth: 1
                }
            },
            scales: {
                x: {
                    grid: {
                        display: false
                    }
                },
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(42, 48, 66, 0.6)'
                    }
                }
            }
        }
    });
}

// Initialize distribution chart
function initDistributionChart() {
    const ctx = document.getElementById('distribution-chart').getContext('2d');
    
    distributionChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Malware', 'Phishing', 'DDoS', 'Ransomware'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: [
                    '#00b0ff',
                    '#ff9500',
                    '#ff3b30',
                    '#5856d6'
                ],
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

// Update trend chart
function updateTrendChart(trends) {
    trendChart.data.labels = trends.days;
    trendChart.data.datasets[0].data = trends.malware;
    trendChart.data.datasets[1].data = trends.phishing;
    trendChart.data.datasets[2].data = trends.ddos;
    trendChart.data.datasets[3].data = trends.ransomware;
    trendChart.update();
}

// Update distribution chart
function updateDistributionChart(trends) {
    // Calculate the totals for each threat type
    const malwareTotal = trends.malware.reduce((a, b) => a + b, 0);
    const phishingTotal = trends.phishing.reduce((a, b) => a + b, 0);
    const ddosTotal = trends.ddos.reduce((a, b) => a + b, 0);
    const ransomwareTotal = trends.ransomware.reduce((a, b) => a + b, 0);
    
    distributionChart.data.datasets[0].data = [
        malwareTotal,
        phishingTotal,
        ddosTotal,
        ransomwareTotal
    ];
    
    distributionChart.update();
}

// Refresh all data
function refreshData() {
    fetchThreats();
    fetchStats();
    fetchTrends();
    updateTimestamp();
}

// Initialize the dashboard
function initDashboard() {
    initTrendChart();
    initDistributionChart();
    refreshData();
    
    // Set up auto-refresh (every 60 seconds)
    setInterval(refreshData, 60000);
    
    // Set up manual refresh button
    refreshBtn.addEventListener('click', function() {
        refreshData();
        
        // Add rotation animation to refresh icon
        const refreshIcon = this.querySelector('i');
        refreshIcon.classList.add('fa-spin');
        setTimeout(() => {
            refreshIcon.classList.remove('fa-spin');
        }, 1000);
    });
}

// Initialize when the DOM is fully loaded
document.addEventListener('DOMContentLoaded', initDashboard);
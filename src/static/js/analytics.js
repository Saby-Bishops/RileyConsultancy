document.addEventListener('DOMContentLoaded', function() {
    // Load initial reports list
    loadReportsList();

    // Set up event listeners
    document.getElementById('report-form').addEventListener('submit', handleReportGeneration);
    document.getElementById('close-preview').addEventListener('click', closeReportPreview);
    document.getElementById('download-report').addEventListener('click', downloadReport);
    
    // Close modal when clicking the X
    document.querySelector('.close-modal').addEventListener('click', function() {
        document.getElementById('report-modal').style.display = 'none';
    });
});

// Global variable to store current report filepath for download
let currentReportPath = '';

/**
 * Load the list of previously generated reports
 */
function loadReportsList() {
    const reportsListBody = document.getElementById('reports-list-body');
    
    fetch('/api/reports')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success' && data.reports.length > 0) {
                reportsListBody.innerHTML = '';
                
                data.reports.forEach(report => {
                    const row = document.createElement('tr');
                    
                    // Format date
                    const reportDate = new Date(report.created_at);
                    const formattedDate = reportDate.toLocaleDateString() + ' ' + 
                                         reportDate.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
                    
                    // Create row content
                    row.innerHTML = `
                        <td>${report.name}</td>
                        <td>${capitalizeFirstLetter(report.type)}</td>
                        <td>${formattedDate}</td>
                        <td class="actions-cell">
                            <button class="btn btn-sm btn-view" data-report-id="${report.id}">
                                <i class="fas fa-eye"></i>
                            </button>
                            <button class="btn btn-sm btn-download" data-filepath="${report.filepath}">
                                <i class="fas fa-download"></i>
                            </button>
                            <button class="btn btn-sm btn-delete" data-report-id="${report.id}">
                                <i class="fas fa-trash"></i>
                            </button>
                        </td>
                    `;
                    
                    reportsListBody.appendChild(row);
                });
                
                // Add event listeners to buttons
                addButtonEventListeners();
            } else {
                reportsListBody.innerHTML = `
                    <tr>
                        <td colspan="4" class="empty-cell">No reports found. Generate a new report to get started.</td>
                    </tr>
                `;
            }
        })
        .catch(error => {
            console.error('Error loading reports:', error);
            reportsListBody.innerHTML = `
                <tr>
                    <td colspan="4" class="error-cell">Error loading reports. Please try again.</td>
                </tr>
            `;
        });
}

/**
 * Add event listeners to the report action buttons
 */
function addButtonEventListeners() {
    // View report buttons
    document.querySelectorAll('.btn-view').forEach(button => {
        button.addEventListener('click', function() {
            const reportId = this.getAttribute('data-report-id');
            viewReport(reportId);
        });
    });
    
    // Download report buttons
    document.querySelectorAll('.btn-download').forEach(button => {
        button.addEventListener('click', function() {
            const filepath = this.getAttribute('data-filepath');
            window.location.href = `/api/reports/${filepath}`;
        });
    });
    
    // Delete report buttons
    document.querySelectorAll('.btn-delete').forEach(button => {
        button.addEventListener('click', function() {
            const reportId = this.getAttribute('data-report-id');
            if (confirm('Are you sure you want to delete this report? This action cannot be undone.')) {
                deleteReport(reportId);
            }
        });
    });
}

/**
 * Handle the report form submission
 */
function handleReportGeneration(event) {
    event.preventDefault();
    
    // Show the progress modal
    const modal = document.getElementById('report-modal');
    modal.style.display = 'block';
    
    // Gather form data
    const reportType = document.getElementById('report-type').value;
    const timeRange = parseInt(document.getElementById('time-range').value);
    
    // Get selected threat types
    const threatTypeCheckboxes = document.querySelectorAll('input[name="threat-types"]:checked');
    const threatTypes = Array.from(threatTypeCheckboxes).map(checkbox => checkbox.value);
    
    // Create request payload
    const payload = {
        report_type: reportType,
        days: timeRange,
        threat_types: threatTypes
    };
    
    // Show status message
    const statusElement = document.getElementById('report-status');
    statusElement.textContent = 'Generating report...';
    statusElement.className = 'alert alert-info';
    statusElement.style.display = 'block';
    
    // Animate progress bar
    simulateProgress();
    
    // Make API request
    fetch('/api/generate_report', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
    })
    .then(response => response.json())
    .then(data => {
        // Hide modal
        modal.style.display = 'none';
        
        if (data.status === 'success') {
            // Update status
            statusElement.textContent = 'Report generated successfully!';
            statusElement.className = 'alert alert-success';
            
            // Store the report path for download
            currentReportPath = data.filepath;
            
            // Preview the report
            displayReportPreview(data.report_content);
            
            // Refresh reports list
            loadReportsList();
            
            // Automatically hide success message after 5 seconds
            setTimeout(() => {
                statusElement.style.display = 'none';
            }, 5000);
        } else {
            throw new Error(data.message || 'Failed to generate report');
        }
    })
    .catch(error => {
        // Hide modal
        modal.style.display = 'none';
        
        // Show error
        statusElement.textContent = `Error: ${error.message}`;
        statusElement.className = 'alert alert-danger';
    });
}

/**
 * Animate the progress bar for visual feedback during report generation
 */
function simulateProgress() {
    const progressFill = document.querySelector('.progress-fill');
    const progressText = document.querySelector('.progress-text');
    
    let width = 0;
    const interval = setInterval(frame, 80);
    
    function frame() {
        if (width >= 90) {
            clearInterval(interval);
            progressText.textContent = 'Finalizing report...';
        } else {
            width += Math.random() * 5;
            progressFill.style.width = width + '%';
            
            if (width > 30 && width < 60) {
                progressText.textContent = 'Analyzing threat intelligence...';
            } else if (width >= 60 && width < 80) {
                progressText.textContent = 'Generating insights...';
            }
        }
    }
}

/**
 * Display the generated report in the preview container
 */
function displayReportPreview(reportContent) {
    const previewContainer = document.getElementById('report-preview-container');
    const contentContainer = document.getElementById('report-content');
    
    // Set the content and display the preview
    contentContainer.innerHTML = reportContent;
    previewContainer.style.display = 'block';
    
    // Scroll to preview
    previewContainer.scrollIntoView({ behavior: 'smooth' });
}

/**
 * Close the report preview
 */
function closeReportPreview() {
    document.getElementById('report-preview-container').style.display = 'none';
}

/**
 * View a previously generated report
 */
function viewReport(reportId) {
    fetch(`/api/reports/${reportId}`)
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                // Store filepath for download button
                currentReportPath = data.filepath;
                
                // Display the report
                displayReportPreview(data.content);
            } else {
                alert(`Error: ${data.message}`);
            }
        })
        .catch(error => {
            console.error('Error viewing report:', error);
            alert('Failed to load report. Please try again.');
        });
}

/**
 * Delete a report
 */
function deleteReport(reportId) {
    fetch(`/api/reports/${reportId}`, {
        method: 'DELETE'
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            // Refresh the reports list
            loadReportsList();
            
            // Show success message
            const statusElement = document.getElementById('report-status');
            statusElement.textContent = 'Report deleted successfully';
            statusElement.className = 'alert alert-success';
            statusElement.style.display = 'block';
            
            // Auto-hide after 3 seconds
            setTimeout(() => {
                statusElement.style.display = 'none';
            }, 3000);
            
            // If the preview is open and showing the deleted report, close it
            if (document.getElementById('report-preview-container').style.display === 'block') {
                closeReportPreview();
            }
        } else {
            alert(`Error: ${data.message}`);
        }
    })
    .catch(error => {
        console.error('Error deleting report:', error);
        alert('Failed to delete report. Please try again.');
    });
}

/**
 * Download the current report
 */
function downloadReport() {
    if (currentReportPath) {
        window.location.href = `/api/reports/${currentReportPath}`;
    } else {
        alert('No report is currently available for download');
    }
}

/**
 * Helper function to capitalize the first letter of a string
 */
function capitalizeFirstLetter(string) {
    return string.charAt(0).toUpperCase() + string.slice(1);
}
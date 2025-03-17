document.addEventListener('DOMContentLoaded', function() {
    // Load threats data from API
    fetchThreats();

    // Set up event handlers
    document.getElementById('import-btn').addEventListener('click', function() {
        window.location.href = '/import';
    });
    
    document.getElementById('export-btn').addEventListener('click', function() {
        window.location.href = '/api/export/threats';
    });
    
    // Add event listeners for filter and export buttons
    document.querySelector('button:has(.fa-filter)').addEventListener('click', toggleFilters);
    document.querySelector('button:has(.fa-download)').addEventListener('click', exportData);
});

async function fetchThreats() {
    try {
        const response = await fetch('/api/threats');
        if (!response.ok) {
            throw new Error('Failed to fetch threat data');
        }
        
        const threats = await response.json();
        displayThreats(threats);
    } catch (error) {
        console.error('Error fetching threats:', error);
        displayError('Failed to load threat data. Please try again later.');
    }
}

function displayThreats(threats) {
    const tableBody = document.getElementById('vulnerability-table-body');
    
    if (!threats || threats.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="4" class="loading-cell">No threat data available...</td></tr>';
        return;
    }
    
    tableBody.innerHTML = '';
    
    threats.forEach(threat => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${threat.first_name} ${threat.last_name}</td>
            <td>${threat.email || 'Not found'}</td>
            <td>
                ${threat.account_count > 0 
                  ? `${threat.account_count} accounts (${threat.unique_sites} sites)` 
                  : 'None found'}
            </td>
            <td>${threat.email_found ? '<span class="found">Yes</span>' : '<span class="not-found">No</span>'}</td>
        `;
        
        // Add click event to show details
        row.dataset.employeeId = threat.employee_id;
        row.addEventListener('click', () => showEmployeeDetails(threat.employee_id));
        
        tableBody.appendChild(row);
    });
}

function displayError(message) {
    const tableBody = document.getElementById('vulnerability-table-body');
    tableBody.innerHTML = `<tr><td colspan="4" class="error-cell">${message}</td></tr>`;
}

async function showEmployeeDetails(employeeId) {
    try {
        const response = await fetch(`/api/employee/${employeeId}`);
        if (!response.ok) {
            throw new Error('Failed to fetch employee details');
        }
        
        const employee = await response.json();
        displayEmployeeModal(employee);
    } catch (error) {
        console.error('Error fetching employee details:', error);
        alert('Failed to load employee details. Please try again later.');
    }
}

function displayEmployeeModal(employee) {
    // Create modal element
    const modal = document.createElement('div');
    modal.className = 'employee-modal';
    
    // Build accounts list HTML
    let accountsHtml = '<h4>Associated Accounts</h4>';
    if (employee.accounts && employee.accounts.length > 0) {
        accountsHtml += '<ul class="accounts-list">';
        employee.accounts.forEach(account => {
            accountsHtml += `<li>
                <strong>${account.site_name}</strong> (${account.category})<br>
                Username: ${account.username}<br>
                <a href="${account.url}" target="_blank">${account.url}</a>
            </li>`;
        });
        accountsHtml += '</ul>';
    } else {
        accountsHtml += '<p>No associated accounts found.</p>';
    }
    
    // Populate modal content
    modal.innerHTML = `
        <div class="modal-content">
            <span class="close-button">&times;</span>
            <h3>${employee.first_name} ${employee.last_name}</h3>
            <div class="employee-details">
                <p><strong>Domain:</strong> ${employee.domain}</p>
                <p><strong>Email:</strong> ${employee.email || 'Not found'} 
                   ${employee.email_score ? `(Confidence: ${employee.email_score.toFixed(1)}%)` : ''}
                </p>
            </div>
            <div class="accounts-section">
                ${accountsHtml}
            </div>
        </div>
    `;
    
    // Add event listener to close button
    modal.querySelector('.close-button').addEventListener('click', () => {
        document.body.removeChild(modal);
    });
    
    // Add modal to body
    document.body.appendChild(modal);
    
    // Close when clicking outside
    modal.addEventListener('click', event => {
        if (event.target === modal) {
            document.body.removeChild(modal);
        }
    });
}

function toggleFilters() {
    // Implementation for filters
    alert('Filter functionality to be implemented');
}

function exportData() {
    window.location.href = '/api/export/threats';
}
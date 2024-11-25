// WebSocket Connection
let socket = null;

function initializeWebSocket() {
    socket = new WebSocket(`ws://${window.location.host}/ws`);
    
    socket.onopen = () => {
        console.log('WebSocket connected');
        updateConnectionStatus('Connected');
    };
    
    socket.onclose = () => {
        console.log('WebSocket disconnected');
        updateConnectionStatus('Disconnected');
        // Try to reconnect after 5 seconds
        setTimeout(initializeWebSocket, 5000);
    };
    
    socket.onmessage = (event) => {
        const data = JSON.parse(event.data);
        handleWebSocketMessage(data);
    };
}

function updateConnectionStatus(status) {
    const statusElement = document.getElementById('connectionStatus');
    if (statusElement) {
        statusElement.textContent = status;
        statusElement.className = `badge bg-${status === 'Connected' ? 'success' : 'danger'}`;
    }
}

function handleWebSocketMessage(data) {
    switch (data.type) {
        case 'event':
            handleNewEvent(data.payload);
            break;
        case 'alert':
            handleNewAlert(data.payload);
            break;
        case 'stats':
            updateDashboardStats(data.payload);
            break;
        default:
            console.warn('Unknown message type:', data.type);
    }
}

function handleNewEvent(event) {
    // Update event table
    const table = document.getElementById('activityTable');
    if (table) {
        const tbody = table.querySelector('tbody');
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${event.timestamp}</td>
            <td>${event.event_type}</td>
            <td>${event.source}</td>
            <td>
                <span class="badge bg-${event.severity_class}">
                    ${event.severity}
                </span>
            </td>
            <td>${event.description}</td>
            <td>
                <button class="btn btn-sm btn-info" onclick="viewDetails(${event.id})">
                    <i class="fas fa-eye"></i>
                </button>
                ${event.has_alert ? `
                    <button class="btn btn-sm btn-warning" onclick="viewAlert(${event.alert_id})">
                        <i class="fas fa-exclamation-triangle"></i>
                    </button>
                ` : ''}
            </td>
        `;
        tbody.insertBefore(row, tbody.firstChild);
        
        // Remove last row if table is too long
        if (tbody.children.length > 100) {
            tbody.removeChild(tbody.lastChild);
        }
    }
    
    // Update timeline chart if exists
    const timelineChart = Chart.getChart('eventTimelineChart');
    if (timelineChart) {
        const labels = timelineChart.data.labels;
        const data = timelineChart.data.datasets[0].data;
        
        // Add new data point
        const hour = new Date(event.timestamp).getHours();
        const index = labels.indexOf(hour);
        if (index !== -1) {
            data[index]++;
        }
        
        timelineChart.update();
    }
}

function handleNewAlert(alert) {
    // Show notification
    showNotification(alert);
    
    // Update alerts count
    const alertsElement = document.querySelector('.alert-count');
    if (alertsElement) {
        const currentCount = parseInt(alertsElement.textContent);
        alertsElement.textContent = currentCount + 1;
    }
    
    // Update distribution chart if exists
    const distributionChart = Chart.getChart('alertDistributionChart');
    if (distributionChart) {
        const data = distributionChart.data.datasets[0].data;
        const labels = distributionChart.data.labels;
        const index = labels.indexOf(alert.severity);
        if (index !== -1) {
            data[index]++;
            distributionChart.update();
        }
    }
}

function updateDashboardStats(stats) {
    // Update overview cards
    Object.entries(stats).forEach(([key, value]) => {
        const element = document.getElementById(`${key}Value`);
        if (element) {
            if (typeof value === 'number' && key.includes('percent')) {
                element.style.width = `${value}%`;
                element.textContent = `${value}%`;
            } else {
                element.textContent = value;
            }
        }
    });
}

function showNotification(alert) {
    // Check if browser supports notifications
    if (!("Notification" in window)) {
        console.warn("This browser does not support desktop notifications");
        return;
    }
    
    // Check if we have permission
    if (Notification.permission === "granted") {
        createNotification(alert);
    } else if (Notification.permission !== "denied") {
        Notification.requestPermission().then(permission => {
            if (permission === "granted") {
                createNotification(alert);
            }
        });
    }
}

function createNotification(alert) {
    const notification = new Notification("SIEM Alert", {
        body: alert.description,
        icon: "/static/img/logo.png",
        tag: alert.id
    });
    
    notification.onclick = () => {
        window.focus();
        viewAlert(alert.id);
    };
}

// Initialize tooltips and popovers
document.addEventListener('DOMContentLoaded', () => {
    // Initialize Bootstrap tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));
    
    // Initialize Bootstrap popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(popoverTriggerEl => new bootstrap.Popover(popoverTriggerEl));
    
    // Initialize WebSocket connection
    initializeWebSocket();
});

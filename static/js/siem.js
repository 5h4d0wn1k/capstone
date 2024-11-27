// SIEM Dashboard JavaScript

// Initialize Socket.IO connection
const socket = io();

// Chart objects
let eventTimelineChart = null;
let alertDistributionChart = null;

// Update system threat level indicator
function updateThreatLevel(level) {
    const threatLevelElement = document.getElementById('threatLevel');
    threatLevelElement.textContent = `Threat Level: ${level}`;
    threatLevelElement.className = `px-4 py-2 rounded ${getThreatLevelClass(level)}`;
}

// Update system health indicator
function updateSystemHealth(health) {
    const healthElement = document.getElementById('systemHealth');
    healthElement.textContent = `System Health: ${health}%`;
    healthElement.className = `px-4 py-2 rounded ${getHealthClass(health)}`;
}

// Add new alert to the alerts list
function addAlert(alert) {
    const alertsList = document.getElementById('alertsList');
    const alertElement = document.createElement('div');
    alertElement.className = `p-4 mb-2 rounded ${getAlertClass(alert.severity)}`;
    alertElement.innerHTML = `
        <div class="flex justify-between items-center">
            <div>
                <h4 class="font-semibold">${alert.title}</h4>
                <p class="text-sm">${alert.description}</p>
            </div>
            <span class="text-sm">${new Date(alert.timestamp).toLocaleTimeString()}</span>
        </div>
    `;
    alertsList.insertBefore(alertElement, alertsList.firstChild);
}

// Initialize dashboard charts
function initCharts() {
    // Event Timeline Chart
    const eventTimelineData = {
        x: [],
        y: [],
        type: 'scatter',
        mode: 'lines',
        name: 'Events',
        line: {
            color: '#3B82F6',
            width: 2
        }
    };

    const eventTimelineLayout = {
        margin: { t: 20, r: 20, b: 40, l: 40 },
        showlegend: false,
        xaxis: {
            title: 'Time',
            showgrid: false
        },
        yaxis: {
            title: 'Events',
            showgrid: true
        }
    };

    eventTimelineChart = Plotly.newPlot('eventTimeline', [eventTimelineData], eventTimelineLayout);

    // Alert Distribution Chart
    const alertDistributionData = {
        values: [0, 0, 0, 0],
        labels: ['Critical', 'High', 'Medium', 'Low'],
        type: 'pie',
        marker: {
            colors: ['#EF4444', '#F59E0B', '#3B82F6', '#10B981']
        }
    };

    const alertDistributionLayout = {
        margin: { t: 20, r: 20, b: 20, l: 20 },
        showlegend: true
    };

    alertDistributionChart = Plotly.newPlot('alertDistribution', [alertDistributionData], alertDistributionLayout);
}

// Utility function to get threat level class
function getThreatLevelClass(level) {
    switch(level.toUpperCase()) {
        case 'CRITICAL': return 'bg-red-600';
        case 'HIGH': return 'bg-orange-500';
        case 'MEDIUM': return 'bg-yellow-500';
        case 'LOW': return 'bg-green-500';
        default: return 'bg-gray-500';
    }
}

// Utility function to get health class
function getHealthClass(health) {
    if (health >= 90) return 'bg-green-500';
    if (health >= 70) return 'bg-yellow-500';
    if (health >= 50) return 'bg-orange-500';
    return 'bg-red-600';
}

// Utility function to get alert class
function getAlertClass(severity) {
    switch(severity.toLowerCase()) {
        case 'critical': return 'bg-red-100 border-l-4 border-red-600';
        case 'high': return 'bg-orange-100 border-l-4 border-orange-500';
        case 'medium': return 'bg-yellow-100 border-l-4 border-yellow-500';
        case 'low': return 'bg-green-100 border-l-4 border-green-500';
        default: return 'bg-gray-100 border-l-4 border-gray-500';
    }
}

// Socket.IO event handlers
socket.on('connect', () => {
    console.log('Connected to SIEM server');
    initCharts();
});

socket.on('disconnect', () => {
    console.log('Disconnected from SIEM server');
});

socket.on('update', (data) => {
    // Update system stats
    document.getElementById('activeAlerts').textContent = data.active_alerts;
    document.getElementById('eventsPerMinute').textContent = data.events_per_minute;
    document.getElementById('networkConnections').textContent = data.network_connections;
    document.getElementById('systemLoad').textContent = `${data.system_load}%`;
    
    // Update threat level and health
    updateThreatLevel(data.threat_level);
    updateSystemHealth(data.system_health);
});

socket.on('new_alert', (alert) => {
    addAlert(alert);
});

socket.on('chart_data', (data) => {
    // Update Event Timeline
    if (data.event_timeline) {
        const update = {
            x: [data.event_timeline.time],
            y: [data.event_timeline.count]
        };
        Plotly.extendTraces('eventTimeline', update, [0]);
    }

    // Update Alert Distribution
    if (data.alert_distribution) {
        const update = {
            values: [
                data.alert_distribution.critical,
                data.alert_distribution.high,
                data.alert_distribution.medium,
                data.alert_distribution.low
            ]
        };
        Plotly.update('alertDistribution', update);
    }
});

// Initialize dashboard on load
document.addEventListener('DOMContentLoaded', () => {
    initCharts();
});

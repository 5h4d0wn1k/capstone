// SIEM Dashboard JavaScript

// Initialize Socket.IO connection with reconnection options
const socket = io({
    reconnection: true,
    reconnectionAttempts: Infinity,
    reconnectionDelay: 1000,
    reconnectionDelayMax: 5000,
    timeout: 20000
});

let eventsPaused = false;
let charts = {};
let reconnectAttempts = 0;
const MAX_EVENTS = 1000;
let eventsQueue = [];

// Connection status handling
socket.on('connect', () => {
    reconnectAttempts = 0;
    updateConnectionStatus(true);
    requestInitialData();
});

socket.on('disconnect', () => {
    updateConnectionStatus(false);
});

socket.on('connect_error', (error) => {
    reconnectAttempts++;
    console.error('Connection error:', error);
    updateConnectionStatus(false, `Connection error (Attempt ${reconnectAttempts})`);
});

function requestInitialData() {
    socket.emit('request_initial_data');
}

function updateConnectionStatus(connected, message = '') {
    const statusIcon = document.querySelector('#connection-status i');
    const statusText = document.querySelector('#connection-status span');
    
    if (connected) {
        statusIcon.className = 'fas fa-circle text-success';
        statusText.textContent = 'Connected';
    } else {
        statusIcon.className = 'fas fa-circle text-danger';
        statusText.textContent = message || 'Disconnected';
    }
}

// Initialize Charts with Error Handling
function initializeCharts() {
    try {
        const chartOptions = {
            chart: {
                type: 'area',
                height: 50,
                sparkline: {
                    enabled: true
                },
                animations: {
                    enabled: true,
                    easing: 'linear',
                    dynamicAnimation: {
                        speed: 1000
                    }
                }
            },
            stroke: {
                curve: 'smooth',
                width: 2
            },
            fill: {
                opacity: 0.3
            },
            series: [{
                name: 'Value',
                data: Array(10).fill(0)
            }],
            tooltip: {
                theme: 'dark',
                fixed: {
                    enabled: false
                },
                x: {
                    show: false
                },
                y: {
                    formatter: function(value) {
                        return value.toFixed(2);
                    }
                }
            },
            noData: {
                text: 'Loading...'
            }
        };

        // CPU Usage Chart
        charts.cpu = new ApexCharts(document.querySelector('#cpu-chart'), {
            ...chartOptions,
            colors: ['#3b82f6'],
            yaxis: {
                min: 0,
                max: 100
            }
        });
        charts.cpu.render();

        // Memory Usage Chart
        charts.memory = new ApexCharts(document.querySelector('#memory-chart'), {
            ...chartOptions,
            colors: ['#22c55e'],
            yaxis: {
                min: 0,
                max: 100
            }
        });
        charts.memory.render();

        // Network Traffic Chart
        charts.network = new ApexCharts(document.querySelector('#network-chart'), {
            ...chartOptions,
            colors: ['#f59e0b']
        });
        charts.network.render();

        // Alerts Chart
        charts.alerts = new ApexCharts(document.querySelector('#alerts-chart'), {
            ...chartOptions,
            colors: ['#ef4444'],
            yaxis: {
                min: 0
            }
        });
        charts.alerts.render();
    } catch (error) {
        console.error('Error initializing charts:', error);
        showError('Failed to initialize charts. Please refresh the page.');
    }
}

// Initialize Threat Map with Error Handling
function initializeThreatMap() {
    try {
        const map = new jsVectorMap({
            selector: '#threat-map',
            map: 'world',
            backgroundColor: 'transparent',
            draggable: true,
            zoomOnScroll: true,
            zoomButtons: true,
            markersSelectable: true,
            markerStyle: {
                initial: {
                    r: 5,
                    fill: '#ff5252',
                    stroke: '#fff',
                    strokeWidth: 1,
                    strokeOpacity: 0.5,
                },
                hover: {
                    fill: '#ff0000',
                    stroke: '#fff',
                }
            },
            regionStyle: {
                initial: {
                    fill: '#2c3e50',
                    stroke: '#243342',
                    strokeWidth: 0.5,
                },
                hover: {
                    fill: '#3498db',
                }
            },
            series: {
                markers: []
            }
        });

        window.threatMap = map;
    } catch (error) {
        console.error('Error initializing threat map:', error);
        showError('Failed to initialize threat map. Please refresh the page.');
    }
}

// Handle System Stats Updates with Error Handling
socket.on('system_stats', (data) => {
    try {
        // Update stat values with validation
        const cpuPercent = validateMetric(data.cpu_percent, 0, 100);
        const memoryPercent = validateMetric(data.memory_percent, 0, 100);
        const networkSpeed = validateMetric(data.network_speed, 0);
        const activeAlerts = validateMetric(data.active_alerts, 0);

        document.querySelector('#cpu-usage').textContent = `${cpuPercent}%`;
        document.querySelector('#memory-usage').textContent = `${memoryPercent}%`;
        document.querySelector('#network-speed').textContent = `${networkSpeed.toFixed(2)} KB/s`;
        document.querySelector('#active-alerts').textContent = activeAlerts;

        // Update charts
        updateChart(charts.cpu, cpuPercent);
        updateChart(charts.memory, memoryPercent);
        updateChart(charts.network, networkSpeed);
        updateChart(charts.alerts, activeAlerts);
    } catch (error) {
        console.error('Error updating system stats:', error);
    }
});

function validateMetric(value, min, max = Infinity) {
    const num = Number(value);
    if (isNaN(num)) return min;
    return Math.min(Math.max(num, min), max);
}

function updateChart(chart, value) {
    if (!chart) return;
    
    try {
        const series = chart.w.globals.series[0];
        const newData = [...series.slice(1), value];
        chart.updateSeries([{ data: newData }]);
    } catch (error) {
        console.error('Error updating chart:', error);
    }
}

// Event Handling with Queue
socket.on('new_event', (event) => {
    if (!eventsPaused) {
        processEvent(event);
    } else {
        queueEvent(event);
    }
});

function processEvent(event) {
    try {
        addEventToTable(event);
        if (event.severity === 'Critical' || event.severity === 'High') {
            addCriticalAlert(event);
        }
        updateThreatMap(event);
    } catch (error) {
        console.error('Error processing event:', error);
    }
}

function queueEvent(event) {
    eventsQueue.push(event);
    if (eventsQueue.length > MAX_EVENTS) {
        eventsQueue.shift();
    }
}

function addEventToTable(event) {
    const table = document.querySelector('#events-table tbody');
    const row = document.createElement('tr');
    
    // Validate and sanitize event data
    const timestamp = event.timestamp ? new Date(event.timestamp).toLocaleString() : 'Unknown';
    const severity = event.severity || 'Unknown';
    const source = escapeHtml(event.source || 'Unknown');
    const message = escapeHtml(event.message || 'No message');
    
    row.innerHTML = `
        <td>${timestamp}</td>
        <td><span class="badge ${getSeverityClass(severity)}">${severity}</span></td>
        <td>${source}</td>
        <td>${message}</td>
    `;
    
    table.insertBefore(row, table.firstChild);
    
    // Limit table rows
    while (table.children.length > MAX_EVENTS) {
        table.removeChild(table.lastChild);
    }
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function getSeverityClass(severity) {
    const classes = {
        'Critical': 'bg-danger',
        'High': 'bg-warning text-dark',
        'Medium': 'bg-info',
        'Low': 'bg-success',
        'Unknown': 'bg-secondary'
    };
    return classes[severity] || classes['Unknown'];
}

function addCriticalAlert(event) {
    const alertsContainer = document.querySelector('#critical-alerts');
    const alert = document.createElement('div');
    
    const timestamp = event.timestamp ? new Date(event.timestamp).toLocaleString() : 'Unknown';
    const message = escapeHtml(event.message || 'No message');
    
    alert.className = 'alert alert-danger alert-dismissible fade show';
    alert.innerHTML = `
        <strong>${timestamp}</strong><br>
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    alertsContainer.insertBefore(alert, alertsContainer.firstChild);
    
    // Limit alerts
    while (alertsContainer.children.length > 5) {
        alertsContainer.removeChild(alertsContainer.lastChild);
    }
}

// Event Controls
document.querySelector('#pause-events').addEventListener('click', (e) => {
    eventsPaused = !eventsPaused;
    e.currentTarget.innerHTML = eventsPaused ? 
        '<i class="fas fa-play"></i> Resume Events' :
        '<i class="fas fa-pause"></i> Pause Events';
    
    if (!eventsPaused && eventsQueue.length > 0) {
        processQueuedEvents();
    }
});

function processQueuedEvents() {
    const events = [...eventsQueue];
    eventsQueue = [];
    events.forEach(processEvent);
}

function showError(message) {
    const alertsContainer = document.querySelector('#critical-alerts');
    const alert = document.createElement('div');
    alert.className = 'alert alert-danger alert-dismissible fade show';
    alert.innerHTML = `
        <strong>Error:</strong> ${escapeHtml(message)}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    alertsContainer.insertBefore(alert, alertsContainer.firstChild);
}

// Initialize components when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    try {
        initializeCharts();
        initializeThreatMap();
    } catch (error) {
        console.error('Error during initialization:', error);
        showError('Failed to initialize dashboard components. Please refresh the page.');
    }
});

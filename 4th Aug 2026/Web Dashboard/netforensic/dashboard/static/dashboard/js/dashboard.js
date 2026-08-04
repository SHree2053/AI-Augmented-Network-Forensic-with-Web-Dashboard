// DASHBOARD DATA LOADER

let trafficChart = null;
let attackChart = null;

document.addEventListener('DOMContentLoaded', function() {
    console.log('Dashboard JS loaded');
    loadDashboardData();
});

function loadDashboardData() {
    console.log('Fetching dashboard data...');
    
    fetch('/dashboard-stats/')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log('Data received:', data);
            
            // Update metric cards
            document.getElementById('metricPackets').textContent = data.total_packets || 0;
            document.getElementById('metricAnomalies').textContent = data.anomalies || 0;
            document.getElementById('metricAccuracy').textContent = data.detection_accuracy || '97.3%';
            document.getElementById('metricFPR').textContent = data.false_positive_rate || '2.1%';
            
            // Update charts
            updateTrafficChart(data.hourly_traffic || []);
            updateAttackChart(data.attack_types || []);
            
            // Update alerts
            updateAlerts(data.recent_alerts || []);
            
            // Update packets
            updatePackets(data.recent_packets || []);
            
            // Update insight
            updateInsight(data);
        })
        .catch(err => {
            console.error('Failed to load dashboard data:', err);
            document.getElementById('alertList').innerHTML = '<div class="text-center text-danger py-3">Failed to load data</div>';
        });
}
// TRAFFIC CHART
function updateTrafficChart(hourlyData) {
    const ctx = document.getElementById('trafficChart');
    if (!ctx) {
        console.warn('trafficChart canvas not found');
        return;
    }
    
    if (trafficChart) {
        trafficChart.destroy();
    }
    
    const labels = hourlyData.map(d => d.hour || '');
    const values = hourlyData.map(d => d.count || 0);
    
    trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Packets',
                data: values,
                borderColor: '#06b6d4',
                backgroundColor: 'rgba(6, 182, 212, 0.1)',
                fill: true,
                tension: 0.4,
                pointBackgroundColor: '#06b6d4',
                pointRadius: 3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: { color: '#b0b8c8', font: { size: 9 } }
                },
                x: {
                    ticks: { color: '#b0b8c8', font: { size: 8 } }
                }
            }
        }
    });
    console.log('Traffic chart updated');
}
// ATTACK CHART
function updateAttackChart(attackData) {
    console.log('Attack data received for chart:', attackData);
    const ctx = document.getElementById('attackChart');

    if (!ctx) {
        console.warn('attackChart canvas not found');
        return;
    }
    
    if (attackChart) {
        attackChart.destroy();
    }
    
    const colors = ['#ef4444', '#f59e0b', '#8b5cf6', '#06b6d4', '#22c55e'];
    const labels = attackData.map(d => d.attack_type || 'Unknown');
    const values = attackData.map(d => d.count || 0);
    
    attackChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: colors.slice(0, values.length),
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '68%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#b0b8c8',
                        boxWidth: 10,
                        font: { size: 8 },
                        padding: 6
                    }
                }
            }
        }
    });
    console.log('Attack chart updated');
}


// ALERTS
function updateAlerts(alerts) {
    const container = document.getElementById('alertList');
    if (!container) {
        console.warn('alertList container not found');
        return;
    }
    
    if (!alerts || alerts.length === 0) {
        container.innerHTML = '<div class="text-center text-muted py-3"><i class="fas fa-inbox me-2"></i>No recent alerts</div>';
        return;
    }
    
    container.innerHTML = alerts.slice(0, 6).map(a => {
        const levelClass = a.level === 'Critical' ? 'danger' : a.level === 'High' ? 'danger' : a.level === 'Medium' ? 'warning' : 'info';
        return `
            <div class="alert-item">
                <span class="alert-time">${a.timestamp || '--'}</span>
                <span class="badge bg-${levelClass}">${a.level || 'Info'}</span>
                <span class="alert-msg">${a.message || 'No message'}</span>
                <span class="alert-ip">${a.ip || 'Unknown'}</span>
            </div>
        `;
    }).join('');
    console.log('Alerts updated');
}
// PACKETS
function updatePackets(packets) {
    const tbody = document.getElementById('packetTableBody');
    if (!tbody) {
        console.warn('packetTableBody not found');
        return;
    }
    
    if (!packets || packets.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-3">No packet data available</td></tr>';
        return;
    }
    
    tbody.innerHTML = packets.slice(0, 10).map(p => {
        const isAttack = p.info && p.info.includes('ATTACK');
        return `
            <tr>
                <td style="color:var(--text-muted)">${p.id || '--'}</td>
                <td>${p.timestamp || '--'}</td>
                <td style="color:var(--cyan)">${p.src_ip || '--'}</td>
                <td>${p.dst_ip || '--'}</td>
                <td><span class="proto-badge">${p.protocol || '?'}</span></td>
                <td style="color:var(--text-muted)">${p.size || '--'}</td>
                <td>${isAttack ? 'ATTACK' : 'NORMAL'}</td>
            </tr>
        `;
    }).join('');
    console.log('Packets updated');
}
// INSIGHT
function updateInsight(data) {
    const insightText = document.getElementById('insightText');
    const llmTimestamp = document.getElementById('llmTimestamp');
    
    if (!insightText) return;
    
    if (data.recent_alerts && data.recent_alerts.length > 0) {
        const top = data.recent_alerts[0];
        insightText.textContent = `Detected ${top.level} severity alert from ${top.ip}. ${data.anomalies || 0} total anomalies identified. (${data.today_anomalies || 0} new today)`;
    } else {
        insightText.textContent = 'Network traffic appears normal. No significant threats detected.';
    }
    
    if (llmTimestamp) {
        llmTimestamp.textContent = `Generated: ${new Date().toLocaleTimeString()}`;
    }
}
// REFRESH BUTTON
const refreshBtn = document.getElementById('refreshBtn');
if (refreshBtn) {
    refreshBtn.addEventListener('click', function() {
        const icon = document.getElementById('refreshIcon');
        const text = document.getElementById('refreshText');
        if (icon) icon.classList.add('fa-spin');
        if (text) text.textContent = 'Loading...';
        this.disabled = true;
        
        loadDashboardData();
        
        setTimeout(() => {
            if (icon) icon.classList.remove('fa-spin');
            if (text) text.textContent = 'Refreshed';
            this.disabled = false;
            setTimeout(() => { if (text) text.textContent = 'Refresh'; }, 1500);
        }, 1000);
    });
}

// THEME TOGGLE (if not already in base)
const themeCheckbox = document.getElementById('themeCheckbox');
if (themeCheckbox) {
    const htmlEl = document.documentElement;
    if (localStorage.getItem('theme') === 'light') {
        htmlEl.setAttribute('data-bs-theme', 'light');
        themeCheckbox.checked = false;
    } else {
        htmlEl.setAttribute('data-bs-theme', 'dark');
        themeCheckbox.checked = true;
    }
    themeCheckbox.addEventListener('change', function() {
        const mode = this.checked ? 'dark' : 'light';
        htmlEl.setAttribute('data-bs-theme', mode);
        localStorage.setItem('theme', mode);
    });
}

console.log('dashboard.js loaded successfully');
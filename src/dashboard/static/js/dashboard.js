/* ============================================================
   Sentinel Firewall — Dashboard JavaScript
   Real-time WebSocket communication + Chart.js visualizations
   ============================================================ */

// --- CSRF Token ---
let CSRF_TOKEN = "";
fetch("/api/csrf-token")
    .then(r => r.json())
    .then(d => { CSRF_TOKEN = d.csrf_token; });

function postJSON(url, body) {
    return fetch(url, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": CSRF_TOKEN,
        },
        body: JSON.stringify(body),
    });
}

// --- Socket.IO Connection ---
const socket = io();

// --- State ---
let bandwidthData = [];
const MAX_BANDWIDTH_POINTS = 60;

// --- Chart Setup ---
const chartColors = {
    primary: '#4f98a3',
    primaryDim: 'rgba(79, 152, 163, 0.1)',
    danger: '#dd6974',
    dangerDim: 'rgba(221, 105, 116, 0.1)',
    success: '#6daa45',
    warning: '#e8af34',
    text: '#8b8ea0',
    grid: '#1f2233',
};

// Bandwidth chart
const bwCtx = document.getElementById('bandwidth-chart').getContext('2d');
const bandwidthChart = new Chart(bwCtx, {
    type: 'line',
    data: {
        labels: [],
        datasets: [
            {
                label: 'Bytes/s',
                data: [],
                borderColor: chartColors.primary,
                backgroundColor: chartColors.primaryDim,
                fill: true,
                tension: 0.4,
                pointRadius: 0,
                borderWidth: 2,
            },
            {
                label: 'Packets/s',
                data: [],
                borderColor: chartColors.warning,
                backgroundColor: 'transparent',
                fill: false,
                tension: 0.4,
                pointRadius: 0,
                borderWidth: 1.5,
                yAxisID: 'y1',
            },
        ],
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { intersect: false, mode: 'index' },
        animation: { duration: 300 },
        plugins: {
            legend: {
                display: true,
                position: 'top',
                align: 'end',
                labels: {
                    color: chartColors.text,
                    font: { size: 11, family: "'Inter', sans-serif" },
                    boxWidth: 12,
                    padding: 12,
                },
            },
        },
        scales: {
            x: {
                display: true,
                grid: { color: chartColors.grid, drawBorder: false },
                ticks: { color: chartColors.text, font: { size: 10 }, maxTicksLimit: 10 },
            },
            y: {
                display: true,
                position: 'left',
                grid: { color: chartColors.grid, drawBorder: false },
                ticks: {
                    color: chartColors.text,
                    font: { size: 10, family: "'JetBrains Mono', monospace" },
                    callback: (v) => formatBytes(v) + '/s',
                },
            },
            y1: {
                display: true,
                position: 'right',
                grid: { drawOnChartArea: false },
                ticks: {
                    color: chartColors.text,
                    font: { size: 10, family: "'JetBrains Mono', monospace" },
                    callback: (v) => v + ' pkt/s',
                },
            },
        },
    },
});

// Protocol distribution chart
const protoCtx = document.getElementById('protocol-chart').getContext('2d');
const protocolChart = new Chart(protoCtx, {
    type: 'doughnut',
    data: {
        labels: [],
        datasets: [{
            data: [],
            backgroundColor: [
                chartColors.primary,
                chartColors.warning,
                chartColors.success,
                chartColors.danger,
                '#a86fdf',
                '#5591c7',
            ],
            borderWidth: 0,
        }],
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '65%',
        plugins: {
            legend: {
                position: 'right',
                labels: {
                    color: chartColors.text,
                    font: { size: 11, family: "'Inter', sans-serif" },
                    padding: 8,
                    boxWidth: 10,
                },
            },
        },
    },
});


// --- WebSocket Handlers ---

socket.on('connect', () => {
    document.getElementById('status-badge').textContent = 'Connected';
    document.getElementById('status-badge').className = 'badge badge-success';
});

socket.on('disconnect', () => {
    document.getElementById('status-badge').textContent = 'Disconnected';
    document.getElementById('status-badge').className = 'badge badge-alert';
});

socket.on('full_state', (data) => {
    updateKPIs(data);
    updateBlocklistStats(data.blocklist);

    if (data.bandwidth_history) {
        bandwidthData = data.bandwidth_history;
        rebuildBandwidthChart();
    }
    if (data.recent_alerts) {
        data.recent_alerts.forEach(a => addAlertItem(a));
    }
    if (data.recent_dns) {
        data.recent_dns.slice(-30).forEach(d => addDNSItem(d));
    }
    if (data.traffic && data.traffic.protocol_counts) {
        updateProtocolChart(data.traffic.protocol_counts);
    }
    if (data.traffic && data.traffic.top_talkers) {
        updateTopTalkers(data.traffic.top_talkers);
    }
});

socket.on('traffic_stats', (data) => {
    // Update KPI cards
    document.getElementById('kpi-packets').textContent = formatNumber(data.packets_captured || 0);
    document.getElementById('kpi-pps').textContent = (data.packets_per_second || 0) + ' pkt/s';
    document.getElementById('kpi-bandwidth').textContent = formatBytes(data.bytes_per_second || 0) + '/s';
    document.getElementById('kpi-total-bytes').textContent = formatBytes(data.bytes_captured || 0) + ' total';

    // Update bandwidth chart
    const now = new Date();
    const label = now.getHours().toString().padStart(2, '0') + ':' +
                  now.getMinutes().toString().padStart(2, '0') + ':' +
                  now.getSeconds().toString().padStart(2, '0');

    bandwidthChart.data.labels.push(label);
    bandwidthChart.data.datasets[0].data.push(data.bytes_per_second || 0);
    bandwidthChart.data.datasets[1].data.push(data.packets_per_second || 0);

    if (bandwidthChart.data.labels.length > MAX_BANDWIDTH_POINTS) {
        bandwidthChart.data.labels.shift();
        bandwidthChart.data.datasets[0].data.shift();
        bandwidthChart.data.datasets[1].data.shift();
    }
    bandwidthChart.update('none');

    // Protocol chart
    if (data.protocol_counts) {
        updateProtocolChart(data.protocol_counts);
    }

    // Top talkers
    if (data.top_talkers) {
        updateTopTalkers(data.top_talkers);
    }

    // Protocol summary
    const protos = Object.keys(data.protocol_counts || {}).join(' / ');
    document.getElementById('protocol-summary').textContent = protos;
});

socket.on('ids_alert', (data) => {
    addAlertItem(data);
    const el = document.getElementById('kpi-alerts');
    el.textContent = parseInt(el.textContent || '0') + 1;
    document.getElementById('alert-count').textContent = el.textContent + ' total';

    // Flash the alert card
    const card = el.closest('.kpi-card');
    card.style.borderColor = 'var(--danger)';
    setTimeout(() => card.style.borderColor = '', 2000);
});

socket.on('dns_event', (data) => {
    addDNSItem(data);
    const total = document.getElementById('kpi-dns-total');
    const blocked = document.getElementById('kpi-dns-blocked');

    if (data.event_type === 'dns_blocked') {
        blocked.textContent = parseInt(blocked.textContent || '0') + 1;
    }
});


// --- UI Update Functions ---

function updateKPIs(data) {
    if (data.traffic) {
        document.getElementById('kpi-packets').textContent = formatNumber(data.traffic.packets_captured || 0);
        document.getElementById('kpi-pps').textContent = (data.traffic.packets_per_second || 0) + ' pkt/s';
        document.getElementById('kpi-bandwidth').textContent = formatBytes(data.traffic.bytes_per_second || 0) + '/s';
        document.getElementById('kpi-total-bytes').textContent = formatBytes(data.traffic.bytes_captured || 0) + ' total';
    }
    if (data.dns) {
        document.getElementById('kpi-dns-blocked').textContent = formatNumber(data.dns.blocked_queries || 0);
        document.getElementById('kpi-dns-total').textContent = 'of ' + formatNumber(data.dns.total_queries || 0) + ' queries';
        document.getElementById('dns-count').textContent = formatNumber(data.dns.total_queries || 0) + ' queries';
    }
    if (data.ids) {
        document.getElementById('kpi-alerts').textContent = formatNumber(data.ids.total_alerts || 0);
        document.getElementById('kpi-rules').textContent = (data.ids.active_rules || 0) + ' active rules';
        document.getElementById('alert-count').textContent = (data.ids.total_alerts || 0) + ' total';
    }
    if (data.uptime) {
        document.getElementById('uptime').textContent = 'Uptime: ' + formatUptime(data.uptime);
    }
}

function updateBlocklistStats(bl) {
    if (!bl) return;
    document.getElementById('bl-domains').textContent = formatNumber(bl.total_blocked_domains || 0);
    document.getElementById('bl-lists').textContent = bl.blocklists_loaded || 0;
    document.getElementById('bl-custom').textContent = bl.custom_blocked || 0;
    document.getElementById('bl-whitelist').textContent = bl.whitelisted || 0;
}

function addAlertItem(data) {
    const list = document.getElementById('alerts-list');
    const empty = list.querySelector('.empty-state');
    if (empty) empty.remove();

    const item = document.createElement('div');
    item.className = 'event-item';
    const severity = data.severity || 'medium';
    const time = formatTime(data.timestamp);
    const msg = data.message || 'Unknown alert';
    const rule = data.data?.rule || '';

    item.innerHTML = `
        <span class="event-time">${time}</span>
        <span class="event-severity ${severity}"></span>
        <span class="event-message"><strong>${rule}</strong> ${msg}</span>
    `;

    list.insertBefore(item, list.firstChild);
    // Keep max 200 items
    while (list.children.length > 200) list.removeChild(list.lastChild);
}

function addDNSItem(data) {
    const list = document.getElementById('dns-list');
    const empty = list.querySelector('.empty-state');
    if (empty) empty.remove();

    const item = document.createElement('div');
    item.className = 'event-item';
    const blocked = data.event_type === 'dns_blocked';
    const severity = blocked ? 'low' : 'info';
    const time = formatTime(data.timestamp);
    const domain = data.data?.domain || data.message || '';
    const prefix = blocked ? '✕ BLOCKED' : '✓ Resolved';

    item.innerHTML = `
        <span class="event-time">${time}</span>
        <span class="event-severity ${severity}"></span>
        <span class="event-message"><strong>${prefix}</strong> ${domain}</span>
    `;

    list.insertBefore(item, list.firstChild);
    while (list.children.length > 200) list.removeChild(list.lastChild);
}

function updateProtocolChart(counts) {
    const labels = Object.keys(counts);
    const values = Object.values(counts);
    protocolChart.data.labels = labels;
    protocolChart.data.datasets[0].data = values;
    protocolChart.update('none');
}

function updateTopTalkers(talkers) {
    const tbody = document.getElementById('top-talkers-body');
    const entries = Object.entries(talkers).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const maxVal = entries.length > 0 ? entries[0][1] : 1;

    tbody.innerHTML = entries.map(([ip, count]) => {
        const pct = Math.round((count / maxVal) * 100);
        return `
            <tr>
                <td>${ip}</td>
                <td>${formatNumber(count)}</td>
                <td class="bar-cell"><div class="bar-fill" style="width:${pct}%"></div></td>
            </tr>
        `;
    }).join('');
}

function rebuildBandwidthChart() {
    bandwidthChart.data.labels = bandwidthData.map(d => {
        const date = new Date(d.time * 1000);
        return date.getHours().toString().padStart(2, '0') + ':' +
               date.getMinutes().toString().padStart(2, '0');
    });
    bandwidthChart.data.datasets[0].data = bandwidthData.map(d => d.bps || 0);
    bandwidthChart.data.datasets[1].data = bandwidthData.map(d => d.pps || 0);
    bandwidthChart.update('none');
}


// --- Domain Block/Unblock ---

function blockDomain() {
    const input = document.getElementById('domain-input');
    const domain = input.value.trim();
    if (!domain) return;

    postJSON('/api/dns/block', { domain })
        .then(r => r.json())
        .then(d => {
            if (d.status === 'ok') {
                input.value = '';
                fetch('/api/stats').then(r => r.json()).then(d => updateBlocklistStats(d.blocklist));
            } else {
                alert('Error: ' + (d.message || d.error));
            }
        });
}

function unblockDomain() {
    const input = document.getElementById('domain-input');
    const domain = input.value.trim();
    if (!domain) return;

    postJSON('/api/dns/unblock', { domain })
        .then(r => r.json())
        .then(d => {
            if (d.status === 'ok') {
                input.value = '';
                fetch('/api/stats').then(r => r.json()).then(d => updateBlocklistStats(d.blocklist));
            } else {
                alert('Error: ' + (d.message || d.error));
            }
        });
}


// --- Uptime ticker ---
let startTime = Date.now();
setInterval(() => {
    fetch('/api/stats').then(r => r.json()).then(data => {
        if (data.uptime) {
            document.getElementById('uptime').textContent = 'Uptime: ' + formatUptime(data.uptime);
        }
    }).catch(() => {});
}, 10000);


// --- Utility Functions ---

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    const val = (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0);
    return val + ' ' + units[Math.min(i, units.length - 1)];
}

function formatNumber(n) {
    if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
    if (n >= 1_000) return (n / 1_000).toFixed(1) + 'K';
    return n.toString();
}

function formatTime(ts) {
    if (!ts) return '--:--';
    const d = new Date(ts * 1000);
    return d.getHours().toString().padStart(2, '0') + ':' +
           d.getMinutes().toString().padStart(2, '0') + ':' +
           d.getSeconds().toString().padStart(2, '0');
}

function formatUptime(seconds) {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    if (h > 0) return h + 'h ' + m + 'm';
    if (m > 0) return m + 'm ' + s + 's';
    return s + 's';
}

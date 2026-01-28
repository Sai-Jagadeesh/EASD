"""
Professional HTML report template for EASD.
Modern dark theme with interactive elements.
"""

HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EASD Report - {{ target }}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #0f1117;
            --bg-surface: #151921;
            --bg-elevated: #1c2230;
            --bg-overlay: #232b3b;
            --bg-hover: rgba(255, 255, 255, 0.04);

            --accent-primary: #6366f1;
            --accent-primary-hover: #818cf8;
            --accent-primary-muted: rgba(99, 102, 241, 0.15);
            --accent-secondary: #22d3ee;
            --accent-tertiary: #a78bfa;

            --color-success: #34d399;
            --color-success-muted: rgba(52, 211, 153, 0.15);
            --color-warning: #fbbf24;
            --color-warning-muted: rgba(251, 191, 36, 0.15);
            --color-danger: #f87171;
            --color-danger-muted: rgba(248, 113, 113, 0.15);
            --color-info: #60a5fa;
            --color-info-muted: rgba(96, 165, 250, 0.15);

            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --text-tertiary: #64748b;
            --text-muted: #475569;

            --border-subtle: rgba(255, 255, 255, 0.06);
            --border-default: rgba(255, 255, 255, 0.1);
            --border-strong: rgba(255, 255, 255, 0.15);

            --shadow-md: 0 4px 12px rgba(0, 0, 0, 0.25);
            --shadow-lg: 0 8px 24px rgba(0, 0, 0, 0.3);

            --radius-sm: 6px;
            --radius-md: 8px;
            --radius-lg: 12px;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-base);
            color: var(--text-primary);
            line-height: 1.6;
            font-size: 14px;
            -webkit-font-smoothing: antialiased;
        }

        /* Sidebar */
        .sidebar {
            position: fixed;
            left: 0;
            top: 0;
            bottom: 0;
            width: 260px;
            background: var(--bg-surface);
            border-right: 1px solid var(--border-subtle);
            display: flex;
            flex-direction: column;
            z-index: 100;
            overflow-y: auto;
        }

        .sidebar-header {
            padding: 20px;
            border-bottom: 1px solid var(--border-subtle);
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 12px;
        }

        .logo-icon {
            width: 40px;
            height: 40px;
            background: linear-gradient(135deg, var(--accent-primary), var(--accent-tertiary));
            border-radius: var(--radius-md);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
            font-weight: 700;
            color: white;
        }

        .logo-text {
            font-size: 20px;
            font-weight: 700;
        }

        .target-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: var(--accent-primary-muted);
            color: var(--accent-primary-hover);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .target-badge::before {
            content: '';
            width: 6px;
            height: 6px;
            background: var(--accent-primary);
            border-radius: 50%;
        }

        .nav-section {
            padding: 16px 12px;
        }

        .nav-title {
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            padding: 0 8px;
            margin-bottom: 8px;
        }

        .nav-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 10px 12px;
            border-radius: var(--radius-md);
            color: var(--text-secondary);
            text-decoration: none;
            cursor: pointer;
            transition: all 0.15s ease;
        }

        .nav-item:hover {
            background: var(--bg-hover);
            color: var(--text-primary);
        }

        .nav-item.active {
            background: var(--accent-primary-muted);
            color: var(--accent-primary-hover);
        }

        .nav-icon { font-size: 18px; }

        .nav-count {
            margin-left: auto;
            background: var(--bg-elevated);
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 12px;
            font-weight: 500;
        }

        /* Main content */
        .main-content {
            margin-left: 260px;
            min-height: 100vh;
        }

        .header {
            background: var(--bg-surface);
            border-bottom: 1px solid var(--border-subtle);
            padding: 16px 24px;
            position: sticky;
            top: 0;
            z-index: 50;
        }

        .header-content {
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .header h1 {
            font-size: 18px;
            font-weight: 600;
        }

        .header-meta {
            display: flex;
            align-items: center;
            gap: 16px;
            color: var(--text-tertiary);
            font-size: 13px;
        }

        .page-content {
            padding: 24px;
            max-width: 1400px;
        }

        /* Metrics Grid */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }

        .metric-card {
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: var(--radius-lg);
            padding: 20px;
            transition: all 0.15s ease;
        }

        .metric-card:hover {
            border-color: var(--border-default);
            box-shadow: var(--shadow-md);
        }

        .metric-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 12px;
        }

        .metric-icon {
            width: 40px;
            height: 40px;
            border-radius: var(--radius-md);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
        }

        .metric-icon.domains { background: var(--accent-primary-muted); color: var(--accent-primary); }
        .metric-icon.ips { background: var(--color-info-muted); color: var(--color-info); }
        .metric-icon.ports { background: var(--color-success-muted); color: var(--color-success); }
        .metric-icon.webapps { background: var(--accent-primary-muted); color: var(--accent-tertiary); }
        .metric-icon.critical { background: var(--color-danger-muted); color: var(--color-danger); }
        .metric-icon.high { background: var(--color-warning-muted); color: var(--color-warning); }
        .metric-icon.medium { background: var(--color-info-muted); color: var(--color-info); }
        .metric-icon.cloud { background: var(--color-success-muted); color: var(--color-success); }

        .metric-value {
            font-size: 32px;
            font-weight: 700;
            line-height: 1;
            margin-bottom: 4px;
        }

        .metric-label {
            font-size: 13px;
            color: var(--text-tertiary);
        }

        /* Section Card */
        .section-card {
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: var(--radius-lg);
            margin-bottom: 20px;
            overflow: hidden;
        }

        .section-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 16px 20px;
            background: var(--bg-elevated);
            border-bottom: 1px solid var(--border-subtle);
            cursor: pointer;
            user-select: none;
        }

        .section-header:hover {
            background: var(--bg-overlay);
        }

        .section-title {
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 15px;
            font-weight: 600;
        }

        .section-icon {
            width: 32px;
            height: 32px;
            border-radius: var(--radius-sm);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 16px;
        }

        .section-icon.subdomains { background: var(--accent-primary-muted); }
        .section-icon.ips { background: var(--color-info-muted); }
        .section-icon.webapps { background: var(--color-success-muted); }
        .section-icon.findings { background: var(--color-danger-muted); }
        .section-icon.cloud { background: var(--color-warning-muted); }
        .section-icon.tech { background: var(--accent-primary-muted); }

        .section-badge {
            font-size: 12px;
            font-weight: 500;
            padding: 4px 12px;
            background: var(--bg-surface);
            border-radius: 10px;
            color: var(--text-secondary);
        }

        .section-content {
            padding: 20px;
        }

        .section-content.collapsed {
            display: none;
        }

        /* Data Table */
        .data-table {
            width: 100%;
            border-collapse: collapse;
        }

        .data-table th {
            text-align: left;
            padding: 12px 16px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            background: var(--bg-elevated);
            border-bottom: 1px solid var(--border-subtle);
        }

        .data-table td {
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-subtle);
            font-size: 13px;
        }

        .data-table tr:hover {
            background: var(--bg-hover);
        }

        .data-table tr:last-child td {
            border-bottom: none;
        }

        /* Tags and Badges */
        .tag {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 500;
        }

        .tag-critical { background: var(--color-danger-muted); color: var(--color-danger); }
        .tag-high { background: var(--color-warning-muted); color: var(--color-warning); }
        .tag-medium { background: var(--color-info-muted); color: var(--color-info); }
        .tag-low { background: var(--color-success-muted); color: var(--color-success); }
        .tag-info { background: var(--bg-elevated); color: var(--text-secondary); }

        .tag-tech {
            background: var(--accent-primary-muted);
            color: var(--accent-primary-hover);
        }

        .tag-alive {
            background: var(--color-success-muted);
            color: var(--color-success);
        }

        .tag-dead {
            background: var(--bg-elevated);
            color: var(--text-muted);
        }

        /* Finding Card */
        .finding-card {
            background: var(--bg-elevated);
            border: 1px solid var(--border-subtle);
            border-radius: var(--radius-md);
            padding: 16px;
            margin-bottom: 12px;
        }

        .finding-card:last-child {
            margin-bottom: 0;
        }

        .finding-header {
            display: flex;
            align-items: flex-start;
            gap: 12px;
            margin-bottom: 8px;
        }

        .finding-severity {
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }

        .finding-severity.critical { background: var(--color-danger-muted); color: var(--color-danger); }
        .finding-severity.high { background: var(--color-warning-muted); color: var(--color-warning); }
        .finding-severity.medium { background: var(--color-info-muted); color: var(--color-info); }
        .finding-severity.low { background: var(--color-success-muted); color: var(--color-success); }
        .finding-severity.info { background: var(--bg-overlay); color: var(--text-secondary); }

        .finding-title {
            font-weight: 600;
            font-size: 14px;
        }

        .finding-description {
            color: var(--text-secondary);
            font-size: 13px;
            line-height: 1.6;
        }

        .finding-meta {
            display: flex;
            gap: 16px;
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid var(--border-subtle);
            font-size: 12px;
            color: var(--text-tertiary);
        }

        /* Grid layouts */
        .grid-2 {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
        }

        /* Search */
        .search-box {
            position: relative;
            margin-bottom: 16px;
        }

        .search-input {
            width: 100%;
            padding: 10px 16px;
            padding-left: 40px;
            background: var(--bg-elevated);
            border: 1px solid var(--border-subtle);
            border-radius: var(--radius-md);
            color: var(--text-primary);
            font-size: 13px;
            font-family: inherit;
        }

        .search-input:focus {
            outline: none;
            border-color: var(--accent-primary);
        }

        .search-icon {
            position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-muted);
        }

        /* Scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }

        ::-webkit-scrollbar-track {
            background: var(--bg-base);
        }

        ::-webkit-scrollbar-thumb {
            background: var(--bg-overlay);
            border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: var(--text-muted);
        }

        /* Code/mono */
        .mono {
            font-family: 'SF Mono', 'Consolas', monospace;
            font-size: 12px;
        }

        /* Tech stack */
        .tech-grid {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }

        /* Empty state */
        .empty-state {
            text-align: center;
            padding: 40px;
            color: var(--text-tertiary);
        }

        .empty-state-icon {
            font-size: 48px;
            margin-bottom: 16px;
            opacity: 0.5;
        }

        @media (max-width: 1200px) {
            .grid-2 { grid-template-columns: 1fr; }
        }

        @media (max-width: 768px) {
            .sidebar { display: none; }
            .main-content { margin-left: 0; }
            .metrics-grid { grid-template-columns: repeat(2, 1fr); }
        }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <nav class="sidebar">
        <div class="sidebar-header">
            <div class="logo">
                <div class="logo-icon">E</div>
                <div class="logo-text">EASD</div>
            </div>
            <div class="target-badge">{{ target }}</div>
        </div>

        <div class="nav-section">
            <div class="nav-title">Overview</div>
            <a href="#overview" class="nav-item active">
                <span class="nav-icon">📊</span>
                <span>Dashboard</span>
            </a>
        </div>

        <div class="nav-section">
            <div class="nav-title">Discovery</div>
            <a href="#subdomains" class="nav-item">
                <span class="nav-icon">🌐</span>
                <span>Subdomains</span>
                <span class="nav-count">{{ stats.subdomains }}</span>
            </a>
            <a href="#ips" class="nav-item">
                <span class="nav-icon">🖥️</span>
                <span>IP Addresses</span>
                <span class="nav-count">{{ stats.ips }}</span>
            </a>
            <a href="#webapps" class="nav-item">
                <span class="nav-icon">🔗</span>
                <span>Web Apps</span>
                <span class="nav-count">{{ stats.webapps }}</span>
            </a>
            <a href="#cloud" class="nav-item">
                <span class="nav-icon">☁️</span>
                <span>Cloud Assets</span>
                <span class="nav-count">{{ stats.cloud }}</span>
            </a>
        </div>

        <div class="nav-section">
            <div class="nav-title">OSINT</div>
            <a href="#github" class="nav-item">
                <span class="nav-icon">🐙</span>
                <span>GitHub Intel</span>
                <span class="nav-count">{{ github_repos|length if github_repos else 0 }}</span>
            </a>
            <a href="#employees" class="nav-item">
                <span class="nav-icon">👤</span>
                <span>Employees</span>
                <span class="nav-count">{{ employees|length if employees else 0 }}</span>
            </a>
        </div>

        <div class="nav-section">
            <div class="nav-title">Analysis</div>
            <a href="#findings" class="nav-item">
                <span class="nav-icon">⚠️</span>
                <span>Findings</span>
                <span class="nav-count">{{ stats.findings }}</span>
            </a>
            <a href="#technologies" class="nav-item">
                <span class="nav-icon">⚙️</span>
                <span>Technologies</span>
            </a>
        </div>
    </nav>

    <!-- Main Content -->
    <main class="main-content">
        <header class="header">
            <div class="header-content">
                <h1>Attack Surface Report</h1>
                <div class="header-meta">
                    <span>Session: {{ session_id }}</span>
                    <span>Generated: {{ generated_at }}</span>
                </div>
            </div>
        </header>

        <div class="page-content">
            <!-- Metrics -->
            <section id="overview">
                <div class="metrics-grid">
                    <div class="metric-card">
                        <div class="metric-header">
                            <div class="metric-icon domains">🌐</div>
                        </div>
                        <div class="metric-value">{{ stats.subdomains }}</div>
                        <div class="metric-label">Subdomains</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-header">
                            <div class="metric-icon ips">🖥️</div>
                        </div>
                        <div class="metric-value">{{ stats.ips }}</div>
                        <div class="metric-label">IP Addresses</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-header">
                            <div class="metric-icon ports">🔌</div>
                        </div>
                        <div class="metric-value">{{ stats.ports }}</div>
                        <div class="metric-label">Open Ports</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-header">
                            <div class="metric-icon webapps">🔗</div>
                        </div>
                        <div class="metric-value">{{ stats.webapps }}</div>
                        <div class="metric-label">Web Applications</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-header">
                            <div class="metric-icon critical">🔴</div>
                        </div>
                        <div class="metric-value">{{ stats.critical }}</div>
                        <div class="metric-label">Critical Findings</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-header">
                            <div class="metric-icon high">🟠</div>
                        </div>
                        <div class="metric-value">{{ stats.high }}</div>
                        <div class="metric-label">High Findings</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-header">
                            <div class="metric-icon medium">🟡</div>
                        </div>
                        <div class="metric-value">{{ stats.medium }}</div>
                        <div class="metric-label">Medium Findings</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-header">
                            <div class="metric-icon cloud">☁️</div>
                        </div>
                        <div class="metric-value">{{ stats.cloud }}</div>
                        <div class="metric-label">Cloud Assets</div>
                    </div>
                </div>
            </section>

            <!-- Findings -->
            <section id="findings" class="section-card">
                <div class="section-header" onclick="toggleSection(this)">
                    <div class="section-title">
                        <div class="section-icon findings">⚠️</div>
                        <span>Security Findings</span>
                    </div>
                    <div class="section-badge">{{ findings|length }} findings</div>
                </div>
                <div class="section-content">
                    {% if findings %}
                    {% for finding in findings %}
                    <div class="finding-card">
                        <div class="finding-header">
                            <span class="finding-severity {{ finding.severity.value }}">{{ finding.severity.value }}</span>
                            <span class="finding-title">{{ finding.title }}</span>
                        </div>
                        <div class="finding-description">{{ finding.description }}</div>
                        {% if finding.affected_asset %}
                        <div class="finding-meta">
                            <span>Asset: <span class="mono">{{ finding.affected_asset }}</span></span>
                            <span>Category: {{ finding.category }}</span>
                        </div>
                        {% endif %}
                    </div>
                    {% endfor %}
                    {% else %}
                    <div class="empty-state">
                        <div class="empty-state-icon">✅</div>
                        <div>No security findings detected</div>
                    </div>
                    {% endif %}
                </div>
            </section>

            <!-- Subdomains -->
            <section id="subdomains" class="section-card">
                <div class="section-header" onclick="toggleSection(this)">
                    <div class="section-title">
                        <div class="section-icon subdomains">🌐</div>
                        <span>Subdomains</span>
                    </div>
                    <div class="section-badge">{{ subdomains|length }} found</div>
                </div>
                <div class="section-content">
                    <div class="search-box">
                        <span class="search-icon">🔍</span>
                        <input type="text" class="search-input" placeholder="Search subdomains..." onkeyup="filterTable(this, 'subdomains-table')">
                    </div>
                    <table class="data-table" id="subdomains-table">
                        <thead>
                            <tr>
                                <th>Subdomain</th>
                                <th>IP Addresses</th>
                                <th>Status</th>
                                <th>Source</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for sub in subdomains %}
                            <tr>
                                <td class="mono">{{ sub.fqdn }}</td>
                                <td class="mono">{{ sub.resolved_ips|join(', ') or '-' }}</td>
                                <td>
                                    {% if sub.is_alive %}
                                    <span class="tag tag-alive">Alive</span>
                                    {% else %}
                                    <span class="tag tag-dead">Unknown</span>
                                    {% endif %}
                                </td>
                                <td>{{ sub.source }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </section>

            <!-- IP Addresses -->
            <section id="ips" class="section-card">
                <div class="section-header" onclick="toggleSection(this)">
                    <div class="section-title">
                        <div class="section-icon ips">🖥️</div>
                        <span>IP Addresses</span>
                    </div>
                    <div class="section-badge">{{ ips|length }} found</div>
                </div>
                <div class="section-content">
                    <div class="search-box">
                        <span class="search-icon">🔍</span>
                        <input type="text" class="search-input" placeholder="Search IPs..." onkeyup="filterTable(this, 'ips-table')">
                    </div>
                    <table class="data-table" id="ips-table">
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>ASN</th>
                                <th>Organization</th>
                                <th>Open Ports</th>
                                <th>Cloud</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for ip in ips %}
                            <tr>
                                <td class="mono">{{ ip.address }}</td>
                                <td>{{ ip.asn or '-' }}</td>
                                <td>{{ ip.asn_org or '-' }}</td>
                                <td class="mono">{{ ip.ports|map(attribute='number')|list|join(', ') or '-' }}</td>
                                <td>
                                    {% if ip.cloud_provider %}
                                    <span class="tag tag-tech">{{ ip.cloud_provider.value }}</span>
                                    {% else %}
                                    -
                                    {% endif %}
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </section>

            <!-- Web Applications -->
            <section id="webapps" class="section-card">
                <div class="section-header" onclick="toggleSection(this)">
                    <div class="section-title">
                        <div class="section-icon webapps">🔗</div>
                        <span>Web Applications</span>
                    </div>
                    <div class="section-badge">{{ webapps|length }} found</div>
                </div>
                <div class="section-content">
                    {% if webapps %}
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>URL</th>
                                <th>Title</th>
                                <th>Status</th>
                                <th>Technologies</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for webapp in webapps %}
                            <tr>
                                <td class="mono"><a href="{{ webapp.url }}" target="_blank" style="color: var(--accent-primary);">{{ webapp.url }}</a></td>
                                <td>{{ webapp.title or '-' }}</td>
                                <td>
                                    <span class="tag {% if webapp.status_code == 200 %}tag-alive{% else %}tag-info{% endif %}">
                                        {{ webapp.status_code }}
                                    </span>
                                </td>
                                <td>
                                    <div class="tech-grid">
                                        {% for tech in webapp.technologies[:5] %}
                                        <span class="tag tag-tech">{{ tech.name }}</span>
                                        {% endfor %}
                                    </div>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                    {% else %}
                    <div class="empty-state">
                        <div class="empty-state-icon">🔗</div>
                        <div>No web applications discovered</div>
                    </div>
                    {% endif %}
                </div>
            </section>

            <!-- Cloud Assets -->
            <section id="cloud" class="section-card">
                <div class="section-header" onclick="toggleSection(this)">
                    <div class="section-title">
                        <div class="section-icon cloud">☁️</div>
                        <span>Cloud Assets</span>
                    </div>
                    <div class="section-badge">{{ cloud_assets|length }} found</div>
                </div>
                <div class="section-content">
                    {% if cloud_assets %}
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Provider</th>
                                <th>Type</th>
                                <th>Name</th>
                                <th>URL</th>
                                <th>Public</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for asset in cloud_assets %}
                            <tr>
                                <td><span class="tag tag-tech">{{ asset.provider.value }}</span></td>
                                <td>{{ asset.asset_type.value }}</td>
                                <td class="mono">{{ asset.name }}</td>
                                <td class="mono">{{ asset.url or '-' }}</td>
                                <td>
                                    {% if asset.is_public %}
                                    <span class="tag tag-critical">PUBLIC</span>
                                    {% else %}
                                    <span class="tag tag-info">Private</span>
                                    {% endif %}
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                    {% else %}
                    <div class="empty-state">
                        <div class="empty-state-icon">☁️</div>
                        <div>No cloud assets discovered</div>
                    </div>
                    {% endif %}
                </div>
            </section>

            <!-- GitHub Intelligence -->
            <section id="github" class="section-card">
                <div class="section-header" onclick="toggleSection(this)">
                    <div class="section-title">
                        <div class="section-icon github">🐙</div>
                        <span>GitHub Intelligence</span>
                    </div>
                    <div class="section-badge">{{ github_repos|length if github_repos else 0 }} repos</div>
                </div>
                <div class="section-content">
                    {% if github_repos %}
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Repository</th>
                                <th>Description</th>
                                <th>Language</th>
                                <th>Stars</th>
                                <th>Updated</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for repo in github_repos %}
                            <tr>
                                <td><a href="{{ repo.url }}" target="_blank" class="link-external">{{ repo.name }}</a></td>
                                <td>{{ repo.description[:80] if repo.description else '-' }}{{ '...' if repo.description and repo.description|length > 80 else '' }}</td>
                                <td><span class="tag tag-tech">{{ repo.language or 'Unknown' }}</span></td>
                                <td>⭐ {{ repo.stars }}</td>
                                <td>{{ repo.updated_at[:10] if repo.updated_at else '-' }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>

                    {% if github_emails %}
                    <h4 style="margin-top: 20px; margin-bottom: 10px; color: var(--text-secondary);">Discovered Commit Emails</h4>
                    <div class="tech-grid">
                        {% for email in github_emails[:30] %}
                        <span class="tag tag-info">{{ email }}</span>
                        {% endfor %}
                        {% if github_emails|length > 30 %}
                        <span class="tag tag-muted">+{{ github_emails|length - 30 }} more</span>
                        {% endif %}
                    </div>
                    {% endif %}
                    {% else %}
                    <div class="empty-state">
                        <div class="empty-state-icon">🐙</div>
                        <div>No GitHub repositories discovered</div>
                    </div>
                    {% endif %}
                </div>
            </section>

            <!-- Employees -->
            <section id="employees" class="section-card">
                <div class="section-header" onclick="toggleSection(this)">
                    <div class="section-title">
                        <div class="section-icon employees">👤</div>
                        <span>Employees &amp; Contacts</span>
                    </div>
                    <div class="section-badge">{{ employees|length if employees else 0 }} found</div>
                </div>
                <div class="section-content">
                    {% if employees %}
                    {% if email_pattern %}
                    <div class="alert alert-info" style="margin-bottom: 15px;">
                        <strong>Email Pattern Detected:</strong> {{ email_pattern }}@domain.com
                    </div>
                    {% endif %}
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Email</th>
                                <th>Name</th>
                                <th>Position</th>
                                <th>Department</th>
                                <th>Source</th>
                                <th>Links</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for emp in employees %}
                            <tr>
                                <td class="mono">{{ emp.email }}</td>
                                <td>{{ emp.first_name }} {{ emp.last_name }}</td>
                                <td>
                                    {% if emp.position %}
                                    {% set pos_lower = emp.position|lower %}
                                    {% if 'ceo' in pos_lower or 'cto' in pos_lower or 'cfo' in pos_lower or 'chief' in pos_lower or 'president' in pos_lower or 'founder' in pos_lower or 'director' in pos_lower or 'vp' in pos_lower %}
                                    <span class="tag tag-warning">{{ emp.position }}</span>
                                    {% else %}
                                    {{ emp.position }}
                                    {% endif %}
                                    {% else %}-{% endif %}
                                </td>
                                <td>{{ emp.department or '-' }}</td>
                                <td><span class="tag tag-info">{{ emp.source }}</span></td>
                                <td>
                                    {% if emp.linkedin %}<a href="{{ emp.linkedin }}" target="_blank" class="link-external">LinkedIn</a>{% endif %}
                                    {% if emp.twitter %}<a href="https://twitter.com/{{ emp.twitter }}" target="_blank" class="link-external">Twitter</a>{% endif %}
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                    {% else %}
                    <div class="empty-state">
                        <div class="empty-state-icon">👤</div>
                        <div>No employees discovered</div>
                    </div>
                    {% endif %}
                </div>
            </section>

            <!-- Technologies Summary -->
            <section id="technologies" class="section-card">
                <div class="section-header" onclick="toggleSection(this)">
                    <div class="section-title">
                        <div class="section-icon tech">⚙️</div>
                        <span>Technology Stack</span>
                    </div>
                </div>
                <div class="section-content">
                    {% if tech_summary %}
                    <div class="tech-grid">
                        {% for tech, count in tech_summary.items() %}
                        <span class="tag tag-tech">{{ tech }} ({{ count }})</span>
                        {% endfor %}
                    </div>
                    {% else %}
                    <div class="empty-state">
                        <div class="empty-state-icon">⚙️</div>
                        <div>No technologies detected</div>
                    </div>
                    {% endif %}
                </div>
            </section>
        </div>
    </main>

    <script>
        function toggleSection(header) {
            const content = header.nextElementSibling;
            content.classList.toggle('collapsed');
            header.classList.toggle('collapsed');
        }

        function filterTable(input, tableId) {
            const filter = input.value.toLowerCase();
            const table = document.getElementById(tableId);
            const rows = table.getElementsByTagName('tr');

            for (let i = 1; i < rows.length; i++) {
                const cells = rows[i].getElementsByTagName('td');
                let found = false;
                for (let j = 0; j < cells.length; j++) {
                    if (cells[j].textContent.toLowerCase().includes(filter)) {
                        found = true;
                        break;
                    }
                }
                rows[i].style.display = found ? '' : 'none';
            }
        }

        // Smooth scroll for nav links
        document.querySelectorAll('.nav-item').forEach(link => {
            link.addEventListener('click', function(e) {
                const href = this.getAttribute('href');
                if (href && href.startsWith('#')) {
                    e.preventDefault();
                    document.querySelector(href).scrollIntoView({ behavior: 'smooth' });
                    document.querySelectorAll('.nav-item').forEach(l => l.classList.remove('active'));
                    this.classList.add('active');
                }
            });
        });
    </script>
</body>
</html>
'''

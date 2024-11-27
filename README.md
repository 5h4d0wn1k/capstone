# Enterprise SIEM System

A professional-grade Security Information and Event Management (SIEM) system with advanced defensive and offensive capabilities.

## Features

### Core Capabilities
- Real-time event monitoring and analysis
- Advanced threat detection using machine learning
- System health monitoring and metrics
- Network traffic analysis
- Comprehensive logging and auditing

### Security Features
- Anomaly detection using Isolation Forest
- Real-time threat level calculation
- Automated alert generation
- Event correlation and analysis
- System health monitoring

### Dashboard
- Real-time metrics and visualization
- Interactive event timeline
- Alert distribution charts
- Live event and alert feeds
- System health indicators

### Monitoring
- Windows Event Log monitoring
- Network traffic analysis
- System resource monitoring
- Process monitoring
- File system monitoring

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd siem
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
# Windows
set SIEM_SECRET_KEY=your-secret-key

# Linux/Mac
export SIEM_SECRET_KEY=your-secret-key
```

## Configuration

The system is configured through `config.yaml`. Key configuration sections:

### System Settings
- Environment (production/development)
- Logging level
- Secret key management

### Monitoring Settings
- Windows event log sources
- Network interface monitoring
- System metrics collection
- Alert thresholds

### Security Settings
- Password policies
- Session management
- IP whitelisting/blacklisting
- Alert severity levels

### Machine Learning
- Anomaly detection parameters
- Model training intervals
- Detection thresholds

## Usage

1. Start the SIEM system:
```bash
python main.py
```

2. Access the dashboard:
```
http://localhost:8080
```

3. Monitor the logs:
```bash
tail -f siem.log
```

## Dashboard Features

### Real-time Monitoring
- Active Alerts Count
- Events per Minute
- Network Connections
- System Load

### Visualization
- Event Timeline
- Alert Distribution
- System Health Metrics
- Threat Level Indicators

### Alert Management
- Real-time Alert Feed
- Severity Classification
- Alert Details
- Response Actions

## Security Considerations

1. Access Control
   - Use strong passwords
   - Implement role-based access
   - Regular credential rotation

2. Network Security
   - Secure all communications
   - Monitor network boundaries
   - Implement proper firewalls

3. Data Protection
   - Encrypt sensitive data
   - Secure storage
   - Regular backups

## Development

### Project Structure
```
siem/
├── main.py              # Main application entry point
├── config.yaml          # Configuration file
├── requirements.txt     # Python dependencies
├── templates/           # HTML templates
│   └── dashboard.html   # Dashboard template
├── modules/            
│   ├── defensive/      # Defensive capabilities
│   └── offensive/      # Offensive capabilities
└── logs/               # Log files
```

### Adding New Features
1. Create new module in appropriate directory
2. Update configuration in config.yaml
3. Add routes/handlers in main.py
4. Update dashboard if needed

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please open an issue in the repository or contact the development team.

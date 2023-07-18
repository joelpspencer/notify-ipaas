# Lookups for iPaaS expected values
# edit left side to match the oracle created alerts, and use the right in the message sent to iPaaS

# not updated with OCI values yet
environment = {
    'development': 'development',
    'demonstration': 'demonstration',
    'disaster recovery': 'disaster recovery',
    'production': 'production',
    'qa': 'qa',
    'staging': 'staging',
    'test': 'test',
    'training': 'training',
}

# not updated with OCI values yet
impact = {
    'CRITICAL': '1 - Extensive/Widespread',
    'ERROR': '2 - Significant/Large',
    'WARNING': '3 - Moderate/Limited',
    'INFO': '4 - Minor/Localized'
}

# not updated with OCI values yet
priority = {
    '1 - Critical': '1 - Critical',
    '2 - High': '2 - High',
    '3 - Medium': '3 - Medium',
    '4 - Low': '4 - Low'
}

# not updated with OCI values yet
source = {
    'chat': 'chat',
    'email': 'email',
    'infrastructure_event': 'infrastructure_event',
    'phone': 'phone',
    'self-service': 'self-service',
    'walk-in': 'walk-in'
}

# not updated with OCI values yet
state = {
    'New': 'New',
    'In Progress': 'In Progress',
    'On Hold': 'On Hold',
    'Resolved': 'Resolved',
    'Closed': 'Closed',
    'Canceled': 'Canceled'
}

# Updated for OCI
urgency = {
    'CRITICAL': '1 - Critical',
    'ERROR': '2 - High',
    'WARNING': '3 - Medium',
    'INFO': '4 - Low'
}
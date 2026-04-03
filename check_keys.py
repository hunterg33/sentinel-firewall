import yaml
config = yaml.safe_load(open('config/default_config.yaml'))
keys = config['threat_intel']['api_keys']
print('abuseipdb:', 'SET' if keys.get('abuseipdb') else 'EMPTY')
print('otx:', 'SET' if keys.get('otx') else 'EMPTY')
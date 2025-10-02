from flask import Flask, jsonify, render_template
import subprocess
from datetime import datetime
import json

app = Flask(__name__)

def run_command(command):
    """Helper function to run a command and return its output."""
    try:
        result = subprocess.check_output(command, shell=True, text=True, stderr=subprocess.STDOUT)
        return result.strip()
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output}"

def parse_system_info(output):
    """Parse the systeminfo command output into a dictionary."""
    info = {}
    lines = output.split('\n')
    
    for line in lines:
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()
            
            important_fields = [
                'OS Name', 'OS Version', 'OS Manufacturer', 
                'System Boot Time', 'Hotfix(s)', 'System Type',
                'Total Physical Memory', 'Available Physical Memory'
            ]
            
            if key in important_fields:
                info[key] = value
                
    return info

    
def get_uptime(boot_time_str):
    """Calculate system uptime using multiple reliable methods."""
    try:
        # Method 1: Direct PowerShell uptime calculation (most reliable)
        ps_command = '''
        powershell "& {
            $bootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
            $uptime = (Get-Date) - $bootTime
            Write-Output (\\\"{0}d {1}h {2}m\\\".Format($uptime.Days, $uptime.Hours, $uptime.Minutes))
        }"
        '''
        result = run_command(ps_command)
        
        if result and not result.startswith('Error'):
            result = result.strip()
            # Validate the format looks correct
            if any(x in result for x in ['d', 'h', 'm']):
                return result

        # Method 3: Fallback to WMIC
        wmic_result = run_command('wmic os get lastbootuptime /format:value')
        if 'LastBootUpTime' in wmic_result:
            for line in wmic_result.split('\n'):
                if 'LastBootUpTime' in line:
                    time_str = line.split('=')[1].strip()
                    # Parse: 20231215143045.500000+000
                    year, month, day = int(time_str[:4]), int(time_str[4:6]), int(time_str[6:8])
                    hour, minute, second = int(time_str[8:10]), int(time_str[10:12]), int(time_str[12:14])
                    boot_time = datetime(year, month, day, hour, minute, second)
                    uptime = datetime.now() - boot_time
                    days = uptime.days
                    hours, remainder = divmod(uptime.seconds, 3600)
                    minutes, seconds = divmod(remainder, 60)
                    return f"{days}d {hours}h {minutes}m"
        
        return "N/A"
        
    except Exception as e:
        return f"Error: {str(e)}"

def check_windows_version_vulnerabilities(os_version):
    """Basic check for well-known Windows vulnerabilities based on version."""
    vulnerabilities = []
    if '10.0.1' in os_version:
        vulnerabilities.append("Outdated Windows 10 version - multiple known vulnerabilities")
    if '6.1' in os_version:  # Windows 7
        vulnerabilities.append("Windows 7 - End of life, critically vulnerable")
    if '6.3' in os_version:  # Windows 8.1
        vulnerabilities.append("Windows 8.1 - Consider upgrading to Windows 10/11")
    if '19041' in os_version:  # Windows 10 2004
        vulnerabilities.append("Windows 10 2004 - Ensure all latest updates are installed")
    return vulnerabilities

# 🔥 FIREWALL CHECK
def check_firewall_status():
    """Check if Windows Firewall is enabled for all profiles"""
    try:
        # Run PowerShell command to get firewall status
        command = 'powershell "Get-NetFirewallProfile | Select-Object Name, Enabled"'
        result = run_command(command)
        
        firewall_status = {}
        lines = result.split('\n')
        
        for line in lines:
            if 'True' in line or 'False' in line:
                parts = line.strip().split()
                if len(parts) >= 2:
                    profile_name = parts[0]
                    is_enabled = parts[1] == 'True'
                    firewall_status[profile_name] = is_enabled
        
        return firewall_status
    
    except Exception as e:
        print(f"Firewall check error: {e}")
        return {'error': str(e)}

# 🖥️ REMOTE DESKTOP CHECK
def check_remote_desktop():
    try:
        command = 'powershell "Get-ItemProperty -Path \'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\' -Name fDenyTSConnections | ConvertTo-Json"'
        result = run_command(command)
        parsed = json.loads(result)
        if parsed.get('fDenyTSConnections') == 0:  # 0 means RDP enabled
            return {'enabled': True, 'status': 'Remote Desktop enabled - Medium Risk'}
        else:
            return {'enabled': False, 'status': 'Remote Desktop disabled'}
    except Exception as e:
        return {'error': str(e)}

@app.route("/")
def index():
    return render_template("index.html")

@app.route('/api/system-info')
def get_system_info():
    try:
        system_info_output = run_command('systeminfo')
        system_info = parse_system_info(system_info_output)

        hotfix_output = run_command('wmic qfe list brief')
        hotfixes = []
        for line in hotfix_output.split('\n'):
            if 'KB' in line:
                parts = line.split()
                if len(parts) >= 3:
                    hotfixes.append({
                        'hotfix_id': parts[0],
                        'description': ' '.join(parts[1:-1]),
                        'installed_on': parts[-1]
                    })

        uptime = get_uptime(system_info.get('System Boot Time', ''))
        firewall_status = check_firewall_status()
        rdp_status = check_remote_desktop()

        risk_findings = []
        if rdp_status.get('enabled', False):
            risk_findings.append(rdp_status.get('status', ''))

        response = {
            'success': True,
            'system_info': system_info,
            'hotfixes': hotfixes[:5],
            'uptime': uptime,
            'firewall_status': firewall_status,
            'rdp_status': rdp_status,
            'risk_findings': risk_findings,
            'total_risks': len(risk_findings),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    except Exception as e:
        response = {'success': False, 'error': str(e)}
    return jsonify(response)


if __name__ == "__main__":
    app.run(debug=True)
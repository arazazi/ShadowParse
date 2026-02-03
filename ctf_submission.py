#!/usr/bin/env python3
"""
Flag Submission Integration
Supports CTFd, HackTheBox, and generic webhook submissions
"""
import requests
from typing import Dict, Optional, List, Any
import json
from pathlib import Path


class FlagSubmitter:
    """Handle flag submissions to various CTF platforms"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.submission_log = []
    
    def _load_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """Load CTF platform configuration"""
        if config_path:
            config_file = Path(config_path)
            if config_file.exists():
                try:
                    import yaml
                    with open(config_file, 'r') as f:
                        return yaml.safe_load(f)
                except Exception as e:
                    print(f"Failed to load config: {e}")
        
        # Default disabled config
        return {
            'ctf_platform': {
                'enabled': False,
                'platform': 'ctfd',
                'url': '',
                'api_token': '',
                'auto_submit': False
            }
        }
    
    def is_enabled(self) -> bool:
        """Check if flag submission is enabled"""
        return self.config.get('ctf_platform', {}).get('enabled', False)
    
    def submit_flag(self, flag: str, challenge_id: Optional[str] = None, 
                    require_confirmation: bool = True) -> Dict[str, Any]:
        """Submit a flag to the configured platform"""
        if not self.is_enabled():
            return {'success': False, 'message': 'Flag submission is disabled'}
        
        platform_config = self.config.get('ctf_platform', {})
        auto_submit = platform_config.get('auto_submit', False)
        
        # Check if confirmation is required
        if require_confirmation and not auto_submit:
            return {
                'success': False,
                'message': 'Flag submission requires confirmation. Use --auto-submit or set auto_submit: true in config.',
                'flag': flag
            }
        
        platform = platform_config.get('platform', 'ctfd').lower()
        
        result = None
        if platform == 'ctfd':
            result = self._submit_to_ctfd(flag, challenge_id, platform_config)
        elif platform == 'htb' or platform == 'hackthebox':
            result = self._submit_to_htb(flag, platform_config)
        elif platform == 'webhook':
            result = self._submit_to_webhook(flag, challenge_id, platform_config)
        else:
            result = {'success': False, 'message': f'Unknown platform: {platform}'}
        
        # Log submission
        self.submission_log.append({
            'flag': flag,
            'platform': platform,
            'result': result,
            'challenge_id': challenge_id
        })
        
        return result
    
    def _submit_to_ctfd(self, flag: str, challenge_id: Optional[str], 
                       config: Dict[str, Any]) -> Dict[str, Any]:
        """Submit flag to CTFd platform"""
        url = config.get('url', '').rstrip('/')
        token = config.get('api_token', '')
        
        if not url or not token:
            return {'success': False, 'message': 'CTFd URL or API token not configured'}
        
        if not challenge_id:
            return {'success': False, 'message': 'Challenge ID is required for CTFd'}
        
        headers = {
            'Authorization': f'Token {token}',
            'Content-Type': 'application/json'
        }
        
        data = {
            'challenge_id': challenge_id,
            'submission': flag
        }
        
        try:
            response = requests.post(
                f'{url}/api/v1/challenges/attempt',
                json=data,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    return {
                        'success': True,
                        'message': 'Flag accepted!',
                        'data': result.get('data', {})
                    }
                else:
                    return {
                        'success': False,
                        'message': result.get('data', {}).get('message', 'Flag incorrect')
                    }
            else:
                return {
                    'success': False,
                    'message': f'HTTP {response.status_code}: {response.text[:100]}'
                }
        except requests.exceptions.Timeout:
            return {'success': False, 'message': 'Request timeout'}
        except Exception as e:
            return {'success': False, 'message': f'Error: {str(e)}'}
    
    def _submit_to_htb(self, flag: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Submit flag to HackTheBox platform"""
        url = config.get('url', '').rstrip('/')
        token = config.get('api_token', '')
        
        if not url or not token:
            return {'success': False, 'message': 'HTB URL or API token not configured'}
        
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        # Determine if it's user.txt or root.txt
        flag_type = 'user' if len(flag) == 32 else 'root'
        
        data = {
            'flag': flag,
            'difficulty': config.get('difficulty', 'medium')
        }
        
        try:
            response = requests.post(
                f'{url}/api/v4/machine/own',
                json=data,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    return {
                        'success': True,
                        'message': f'Flag accepted ({flag_type})!',
                        'data': result
                    }
                else:
                    return {
                        'success': False,
                        'message': result.get('message', 'Flag incorrect')
                    }
            else:
                return {
                    'success': False,
                    'message': f'HTTP {response.status_code}: {response.text[:100]}'
                }
        except requests.exceptions.Timeout:
            return {'success': False, 'message': 'Request timeout'}
        except Exception as e:
            return {'success': False, 'message': f'Error: {str(e)}'}
    
    def _submit_to_webhook(self, flag: str, challenge_id: Optional[str], 
                          config: Dict[str, Any]) -> Dict[str, Any]:
        """Submit flag to a generic webhook"""
        url = config.get('webhook_url', '')
        
        if not url:
            return {'success': False, 'message': 'Webhook URL not configured'}
        
        headers = config.get('webhook_headers', {})
        headers['Content-Type'] = 'application/json'
        
        from datetime import datetime
        data = {
            'flag': flag,
            'challenge_id': challenge_id,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            response = requests.post(
                url,
                json=data,
                headers=headers,
                timeout=10
            )
            
            if 200 <= response.status_code < 300:
                return {
                    'success': True,
                    'message': 'Flag submitted to webhook',
                    'status_code': response.status_code
                }
            else:
                return {
                    'success': False,
                    'message': f'HTTP {response.status_code}: {response.text[:100]}'
                }
        except requests.exceptions.Timeout:
            return {'success': False, 'message': 'Request timeout'}
        except Exception as e:
            return {'success': False, 'message': f'Error: {str(e)}'}
    
    def get_submission_log(self) -> List[Dict[str, Any]]:
        """Get all submission attempts"""
        return self.submission_log
    
    def save_submission_log(self, output_path: Path):
        """Save submission log to file"""
        log_file = output_path / "flag_submissions.log"
        try:
            with open(log_file, 'w') as f:
                for entry in self.submission_log:
                    f.write(f"Flag: {entry['flag']}\n")
                    f.write(f"Platform: {entry['platform']}\n")
                    f.write(f"Challenge ID: {entry.get('challenge_id', 'N/A')}\n")
                    f.write(f"Result: {entry['result']}\n")
                    f.write("-" * 50 + "\n")
        except Exception as e:
            print(f"Failed to save submission log: {e}")


def create_config_template(output_path: Path):
    """Create a template configuration file"""
    template = """# CTF Platform Configuration
ctf_platform:
  enabled: false  # Set to true to enable flag submission
  platform: "ctfd"  # Options: "ctfd", "htb", "webhook"
  url: "https://ctf.example.com"
  api_token: "your-api-token-here"
  auto_submit: false  # Set to true to auto-submit without confirmation
  
  # For webhook platform
  webhook_url: "https://your-webhook.com/submit"
  webhook_headers:
    Authorization: "Bearer your-token"
    X-Custom-Header: "custom-value"

# Example CTFd configuration:
# ctf_platform:
#   enabled: true
#   platform: "ctfd"
#   url: "https://ctfd.example.com"
#   api_token: "your-ctfd-api-token"
#   auto_submit: false

# Example HTB configuration:
# ctf_platform:
#   enabled: true
#   platform: "htb"
#   url: "https://www.hackthebox.eu"
#   api_token: "your-htb-api-token"
#   auto_submit: false
"""
    
    config_file = output_path / "ctf_config.yaml"
    try:
        with open(config_file, 'w') as f:
            f.write(template)
        print(f"Created config template: {config_file}")
    except Exception as e:
        print(f"Failed to create config template: {e}")

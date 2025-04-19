# monetization/licensing.py
import jwt
import time
import base64
import uuid
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import hashlib
import json
import secrets
from typing import Dict, List

class LicenseManager:
    """Handle software licensing and activation"""
    
    def __init__(self, secret_key: str):
        # Valida tamanho mínimo da chave
        if len(secret_key) < 32:
            raise ValueError("Secret key must be at least 32 characters")
        
        self.secret_key = secret_key
        self.fernet = Fernet(self._get_fernet_key())
        
        # Algoritmo seguro para JWT
        self.jwt_algorithm = 'HS384'
    
    def _get_fernet_key(self) -> bytes:
        """Generate Fernet key from secret"""
        # Usa derivação de chave segura
        return base64.urlsafe_b64encode(
        hashlib.sha256(self.secret_key.encode()).digest()[:32]
    )
    
    def generate_license(self, 
                        user_email: str, 
                        plan: str = "basic", 
                        duration_days: int = 30) -> str:
        """Generate a new license key"""
        
        # Valida email
        if not self._is_valid_email(user_email):
            raise ValueError("Invalid email format")
        
        # Valida plano
        if plan not in ["basic", "pro", "enterprise"]:
            raise ValueError(f"Invalid plan: {plan}")
        
        issued_at = datetime.utcnow()
        expires_at = issued_at + timedelta(days=duration_days)
        
        license_data = {
            'license_id': str(uuid.uuid4()),
            'user_email': user_email,
            'plan': plan,
            'issued_at': issued_at.isoformat(),
            'expires_at': expires_at.isoformat(),
            'features': self._get_plan_features(plan),
            'max_analyses': self._get_max_analyses(plan),
            'api_rate_limit': self._get_api_rate_limit(plan),
            'iat': int(issued_at.timestamp()),  # Issued at timestamp
            'exp': int(expires_at.timestamp()),  # Expiration timestamp
            'jti': str(uuid.uuid4()),  # JWT ID único
            'kid': secrets.token_hex(16)  # Key ID para rotação
        }
        
        # Encode with JWT usando algoritmo seguro
        token = jwt.encode(
            license_data, 
            self.secret_key, 
            algorithm=self.jwt_algorithm
        )
        
        # Encrypt for extra security
        encrypted = self.fernet.encrypt(token.encode())
        
        return encrypted.decode()
    
    def validate_license(self, license_key: str) -> Dict:
        """Validate a license key and return license info"""
        try:
            # Decrypt
            decrypted = self.fernet.decrypt(license_key.encode())
            
            # Decode JWT
            license_data = jwt.decode(
                decrypted, 
                self.secret_key, 
                algorithms=[self.jwt_algorithm],
                options={
                    'verify_exp': True,  # Verifica expiração
                    'verify_iat': True,  # Verifica issued at
                    'require': ['exp', 'iat', 'jti']  # Campos obrigatórios
                }
            )
            
            # Validações adicionais
            expires_at = datetime.fromisoformat(license_data['expires_at'])
            if datetime.utcnow() > expires_at:
                raise ValueError("License expired")
            
            # Verifica se a licença está na blacklist (revogada)
            if self._is_license_revoked(license_data['license_id']):
                raise ValueError("License has been revoked")
            
            return license_data
            
        except jwt.ExpiredSignatureError:
            raise ValueError("License expired")
        except jwt.InvalidTokenError:
            raise ValueError("Invalid license format")
        except Exception as e:
            raise ValueError(f"Invalid license: {str(e)}")
    
    def _is_valid_email(self, email: str) -> bool:
        """Validate email format"""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def _is_license_revoked(self, license_id: str) -> bool:
        """Check if license has been revoked"""
        # Em produção, verificar contra banco de dados de licenças revogadas
        # Por enquanto retorna False
        return False
    
    def _get_plan_features(self, plan: str) -> List[str]:
        """Get features for each plan"""
        features = {
            'basic': [
                'binary_analysis',
                'string_extraction',
                'function_analysis'
            ],
            'pro': [
                'binary_analysis',
                'string_extraction', 
                'function_analysis',
                'exploit_generation',
                'vulnerability_detection',
                'api_access'
            ],
            'enterprise': [
                'binary_analysis',
                'string_extraction',
                'function_analysis',
                'exploit_generation',
                'vulnerability_detection',
                'api_access',
                'dynamic_analysis',
                'binary_diffing',
                'custom_reports',
                'priority_support',
                'exploit_marketplace'
            ]
        }
        return features.get(plan, features['basic'])
    
    def _get_max_analyses(self, plan: str) -> int:
        """Get max analyses per month for plan"""
        limits = {
            'basic': 100,
            'pro': 1000,
            'enterprise': -1  # Unlimited
        }
        return limits.get(plan, 100)
    
    def _get_api_rate_limit(self, plan: str) -> int:
        """Get API rate limit (requests/hour)"""
        limits = {
            'basic': 100,
            'pro': 1000,
            'enterprise': 10000
        }
        return limits.get(plan, 100)
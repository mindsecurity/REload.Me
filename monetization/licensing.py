# monetization/licensing.py
import jwt
import time
import uuid
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import hashlib
import json

class LicenseManager:
    """Handle software licensing and activation"""
    
    def __init__(self, secret_key: str):
        self.secret_key = secret_key
        self.fernet = Fernet(self._get_fernet_key())
    
    def _get_fernet_key(self) -> bytes:
        """Generate Fernet key from secret"""
        return hashlib.sha256(self.secret_key.encode()).digest()[:32]
    
    def generate_license(self, 
                        user_email: str, 
                        plan: str = "basic", 
                        duration_days: int = 30) -> str:
        """Generate a new license key"""
        
        license_data = {
            'license_id': str(uuid.uuid4()),
            'user_email': user_email,
            'plan': plan,
            'issued_at': datetime.utcnow().isoformat(),
            'expires_at': (datetime.utcnow() + timedelta(days=duration_days)).isoformat(),
            'features': self._get_plan_features(plan),
            'max_analyses': self._get_max_analyses(plan),
            'api_rate_limit': self._get_api_rate_limit(plan)
        }
        
        # Encode with JWT
        token = jwt.encode(license_data, self.secret_key, algorithm='HS256')
        
        # Encrypt for extra security
        encrypted = self.fernet.encrypt(token.encode())
        
        return encrypted.decode()
    
    def validate_license(self, license_key: str) -> Dict:
        """Validate a license key and return license info"""
        try:
            # Decrypt
            decrypted = self.fernet.decrypt(license_key.encode())
            
            # Decode JWT
            license_data = jwt.decode(decrypted, self.secret_key, algorithms=['HS256'])
            
            # Check expiration
            expires_at = datetime.fromisoformat(license_data['expires_at'])
            if datetime.utcnow() > expires_at:
                raise ValueError("License expired")
            
            return license_data
            
        except Exception as e:
            raise ValueError(f"Invalid license: {str(e)}")
    
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
                'priority_support'
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


# Example usage in main application:
class BillingSystem:
    """Integration with payment systems and subscription management"""
    
    def __init__(self, stripe_api_key: str, db_connection):
        self.stripe = stripe
        self.stripe.api_key = stripe_api_key
        self.db = db_connection
    
    def create_subscription(self, user_id: str, plan: str) -> str:
        """Create a new subscription for user"""
        # Get or create customer
        customer = self._get_or_create_customer(user_id)
        
        # Create subscription
        price_id = self._get_price_id(plan)
        subscription = self.stripe.Subscription.create(
            customer=customer.id,
            items=[{'price': price_id}],
            metadata={'user_id': user_id},
            trial_period_days=14  # Free trial
        )
        
        # Update database
        self.db.execute("""
            INSERT OR REPLACE INTO subscriptions 
            (user_id, stripe_subscription_id, plan, status, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, subscription.id, plan, subscription.status, datetime.utcnow()))
        
        return subscription.id
    
    def _get_or_create_customer(self, user_id: str) -> stripe.Customer:
        """Get existing customer or create new one"""
        # Check if customer exists
        result = self.db.execute(
            "SELECT stripe_customer_id FROM users WHERE id = ?", 
            (user_id,)
        ).fetchone()
        
        if result and result['stripe_customer_id']:
            return self.stripe.Customer.retrieve(result['stripe_customer_id'])
        
        # Create new customer
        user_data = self.db.execute(
            "SELECT email, name FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()
        
        customer = self.stripe.Customer.create(
            email=user_data['email'],
            name=user_data['name'],
            metadata={'user_id': user_id}
        )
        
        # Update database
        self.db.execute(
            "UPDATE users SET stripe_customer_id = ? WHERE id = ?",
            (customer.id, user_id)
        )
        
        return customer
    
    def _get_price_id(self, plan: str) -> str:
        """Get Stripe price ID for plan"""
        price_map = {
            'basic': 'price_basic_monthly',
            'pro': 'price_pro_monthly',
            'enterprise': 'price_enterprise_monthly'
        }
        return price_map.get(plan, price_map['basic'])
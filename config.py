# config.py
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Application configuration"""
    
    # Database
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///reloadai.db")
    
    # Security
    SECRET_KEY = os.getenv("SECRET_KEY", os.urandom(32).hex())
    LICENSE_SECRET_KEY = os.getenv("LICENSE_SECRET_KEY", os.urandom(32).hex())
    
    # API Keys
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    STRIPE_API_KEY = os.getenv("STRIPE_API_KEY")
    STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
    
    # Redis (for caching and rate limiting)
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    
    # Radare2
    R2_PATH = os.getenv("R2_PATH", "r2")
    
    # Plans and limits
    PLANS = {
        'basic': {
            'price': 49,
            'analyses_per_month': 100,
            'api_rate_limit': 100,  # requests per hour
            'features': [
                'binary_analysis',
                'string_extraction',
                'function_analysis'
            ]
        },
        'pro': {
            'price': 149,
            'analyses_per_month': 1000,
            'api_rate_limit': 1000,
            'features': [
                'binary_analysis',
                'string_extraction',
                'function_analysis',
                'exploit_generation',
                'vulnerability_detection',
                'api_access'
            ]
        },
        'enterprise': {
            'price': 499,
            'analyses_per_month': -1,  # Unlimited
            'api_rate_limit': 10000,
            'features': [
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
    }
    
    # Analysis settings
    MAX_BINARY_SIZE = 50 * 1024 * 1024  # 50MB
    ANALYSIS_TIMEOUT = 300  # 5 minutes
    THREAD_POOL_SIZE = 5
    
    # Marketplace settings
    MARKETPLACE_COMMISSION = 0.3  # 30%
    EXPLOIT_TEST_TIMEOUT = 60  # 1 minute
    
    # File storage
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "uploads")
    ALLOWED_EXTENSIONS = {'bin', 'exe', 'elf', 'so', 'dll', 'dylib'}
    
    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE = os.getenv("LOG_FILE", "reloadai.log")
    
    # API Settings
    API_HOST = os.getenv("API_HOST", "0.0.0.0")
    API_PORT = int(os.getenv("API_PORT", 8000))
    API_WORKERS = int(os.getenv("API_WORKERS", 4))
    
    # Frontend settings
    FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")
    
    # Email settings (for notifications)
    SMTP_SERVER = os.getenv("SMTP_SERVER")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
    SMTP_USERNAME = os.getenv("SMTP_USERNAME")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
    SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "noreply@reloadai.com")
    
    # Cloud storage (for report artifacts)
    AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
    AWS_S3_BUCKET = os.getenv("AWS_S3_BUCKET", "reloadai-reports")
    AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
    
    # Sandbox configuration
    SANDBOX_TYPE = os.getenv("SANDBOX_TYPE", "docker")  # docker, qemu, or none
    SANDBOX_IMAGES = {
        'ubuntu': 'reloadai/sandbox:ubuntu-latest',
        'alpine': 'reloadai/sandbox:alpine-latest',
        'windows': 'reloadai/sandbox:windows-latest'
    }
    
    # Feature flags
    FEATURES = {
        'exploit_generation': os.getenv("FEATURE_EXPLOIT_GENERATION", "true").lower() == "true",
        'dynamic_analysis': os.getenv("FEATURE_DYNAMIC_ANALYSIS", "true").lower() == "true",
        'binary_diffing': os.getenv("FEATURE_BINARY_DIFFING", "false").lower() == "true",
        'marketplace': os.getenv("FEATURE_MARKETPLACE", "true").lower() == "true",
        'custom_malware': os.getenv("FEATURE_CUSTOM_MALWARE", "false").lower() == "true",
        'ctf_solver': os.getenv("FEATURE_CTF_SOLVER", "false").lower() == "true"
    }
    
    @classmethod
    def is_feature_enabled(cls, feature: str) -> bool:
        """Check if a feature is enabled"""
        return cls.FEATURES.get(feature, False)
    
    @classmethod
    def validate(cls):
        """Validate configuration"""
        required_keys = ['OPENAI_API_KEY', 'STRIPE_API_KEY']
        for key in required_keys:
            if not getattr(cls, key):
                raise ValueError(f"Missing required configuration: {key}")
        
        if not os.path.exists(cls.UPLOAD_FOLDER):
            os.makedirs(cls.UPLOAD_FOLDER)
    
    @classmethod
    def get_plan_features(cls, plan: str):
        """Get features for a specific plan"""
        return cls.PLANS.get(plan, cls.PLANS['basic'])['features']
    
    @classmethod
    def get_plan_limits(cls, plan: str):
        """Get limits for a specific plan"""
        plan_config = cls.PLANS.get(plan, cls.PLANS['basic'])
        return {
            'analyses_per_month': plan_config['analyses_per_month'],
            'api_rate_limit': plan_config['api_rate_limit']
        }

# Create .env.example file
env_example = """
# Required keys
OPENAI_API_KEY=your_openai_api_key
STRIPE_API_KEY=your_stripe_api_key
STRIPE_WEBHOOK_SECRET=your_stripe_webhook_secret

# Optional keys
DATABASE_URL=sqlite:///reloadai.db
REDIS_URL=redis://localhost:6379/0
SECRET_KEY=your_secret_key
LICENSE_SECRET_KEY=your_license_secret_key

# API settings
API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=4

# Frontend settings
FRONTEND_URL=http://localhost:3000
CORS_ORIGINS=http://localhost:3000,https://yourdomain.com

# Email settings (optional)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password
SMTP_FROM_EMAIL=noreply@reloadai.com

# AWS settings (optional, for cloud storage)
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AWS_S3_BUCKET=reloadai-reports
AWS_REGION=us-east-1

# Feature flags
FEATURE_EXPLOIT_GENERATION=true
FEATURE_DYNAMIC_ANALYSIS=true
FEATURE_BINARY_DIFFING=false
FEATURE_MARKETPLACE=true
FEATURE_CUSTOM_MALWARE=false
FEATURE_CTF_SOLVER=false
"""

if __name__ == "__main__":
    # Create .env.example file
    with open(".env.example", "w") as f:
        f.write(env_example.strip())
    
    # Validate configuration
    try:
        Config.validate()
        print("Configuration validated successfully!")
    except ValueError as e:
        print(f"Configuration error: {e}")
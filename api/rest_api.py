from fastapi import FastAPI, File, UploadFile, Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, validator
from typing import Optional, List, Dict
import uuid
import os
import tempfile
import shutil
import logging
import magic  # python-magic library
import redis
from datetime import datetime, timedelta
import asyncio
from functools import wraps
import hashlib
import json

from monetization.licensing import LicenseManager
from monetization.analytics import UsageAnalytics
from database import get_db, Database
from config import Config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="REloadAI API",
    description="Automated binary analysis and exploit generation",
    version="2.0.1",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=Config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Redis for rate limiting
redis_client = redis.Redis.from_url(Config.REDIS_URL)

# Initialize components
license_manager = LicenseManager(Config.LICENSE_SECRET_KEY)

# Rate limit decorator
def rate_limit(requests: int, window: int):
    """Rate limit decorator for endpoints"""
    def decorator(func):
        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            # Obtém IP do cliente
            client_ip = request.client.host
            key = f"rate_limit:{func.__name__}:{client_ip}"
            
            # Incrementa contador
            count = redis_client.incr(key)
            if count == 1:
                redis_client.expire(key, window)
            
            if count > requests:
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded. Max {requests} requests per {window} seconds"
                )
            
            return await func(request, *args, **kwargs)
        return wrapper
    return decorator

# Models com validações
class AnalysisRequest(BaseModel):
    features: List[str] = ["basic_analysis", "string_extraction"]
    language: str = "python"
    generate_exploit: bool = False
    
    @validator('features')
    def validate_features(cls, v):
        allowed = [
            "basic_analysis", "string_extraction", "function_analysis",
            "exploit_generation", "vulnerability_detection", "dynamic_analysis"
        ]
        for feature in v:
            if feature not in allowed:
                raise ValueError(f"Invalid feature: {feature}")
        return v
    
    @validator('language')
    def validate_language(cls, v):
        allowed = ["python", "c", "golang", "rust"]
        if v not in allowed:
            raise ValueError(f"Invalid language: {v}")
        return v

class AnalysisResponse(BaseModel):
    analysis_id: str
    status: str
    task_id: Optional[str] = None
    file_info: Optional[Dict] = None
    protections: Optional[Dict] = None
    strings: Optional[List[Dict]] = None
    functions: Optional[List[Dict]] = None
    vulnerabilities: Optional[List[Dict]] = None
    exploit_code: Optional[str] = None
    mitigations: Optional[str] = None

class ExploitListingRequest(BaseModel):
    title: str
    description: str
    exploit_type: str
    code: str
    price: float
    test_binary: Optional[str] = None
    
    @validator('title')
    def validate_title(cls, v):
        if len(v) < 5 or len(v) > 100:
            raise ValueError("Title must be between 5 and 100 characters")
        return v
    
    @validator('price')
    def validate_price(cls, v):
        if v < 0 or v > 10000:
            raise ValueError("Price must be between 0 and 10000")
        return v

# Dependency for authentication and rate limiting
async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Database = Depends(get_db)
):
    """Validate license key and return user info"""
    try:
        license_info = license_manager.validate_license(credentials.credentials)
        
        # Get user from database
        user = db.execute(
            "SELECT * FROM users WHERE email = ?",
            (license_info['user_email'],)
        ).fetchone()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Check rate limiting por usuário
        key = f"rate_limit:user:{user['id']}:{datetime.utcnow().strftime('%Y-%m-%d-%H')}"
        current_count = redis_client.incr(key)
        if current_count == 1:
            redis_client.expire(key, 3600)  # 1 hour expiry
        
        if current_count > license_info['api_rate_limit']:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        
        return {
            'user_id': user['id'],
            'email': user['email'],
            'plan': license_info['plan'],
            'features': license_info['features'],
            'api_rate_limit': license_info['api_rate_limit']
        }
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

# Middleware para logging de segurança
@app.middleware("http")
async def security_logging_middleware(request: Request, call_next):
    """Log de todas as requisições para auditoria"""
    start_time = datetime.utcnow()
    
    # Gera request ID único
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    
    # Log request
    logger.info(f"Request ID: {request_id} | Method: {request.method} | Path: {request.url.path}")
    
    try:
        response = await call_next(request)
        
        # Log response
        duration = (datetime.utcnow() - start_time).total_seconds()
        logger.info(f"Request ID: {request_id} | Status: {response.status_code} | Duration: {duration:.2f}s")
        
        return response
    except Exception as e:
        # Log error
        logger.error(f"Request ID: {request_id} | Error: {str(e)}")
        raise

# Routes
@app.post("/api/v1/analyze", response_model=AnalysisResponse)
@rate_limit(requests=10, window=60)  # 10 requests per minute
async def analyze_binary(
    request: Request,
    file: UploadFile = File(...),
    analysis_request: AnalysisRequest = Depends(),
    current_user: Dict = Depends(get_current_user),
    db: Database = Depends(get_db)
):
    """Analyze a binary file"""
    analysis_id = str(uuid.uuid4())
    
    # Check if user has feature access
    for feature in analysis_request.features:
        if feature not in current_user['features']:
            raise HTTPException(
                status_code=403, 
                detail=f"Feature '{feature}' not available in your plan"
            )
    
    # Validate file size
    file_content = await file.read()
    file_size = len(file_content)
    await file.seek(0)  # Reset file pointer
    
    if file_size > Config.MAX_BINARY_SIZE:
        raise HTTPException(
            status_code=400, 
            detail=f"File too large. Max size: {Config.MAX_BINARY_SIZE/1024/1024}MB"
        )
    
    # Validate file type
    mime_type = magic.from_buffer(file_content, mime=True)
    allowed_mimes = [
        'application/x-executable', 'application/x-dosexec', 
        'application/x-object', 'application/x-sharedlib',
        'application/x-mach-binary'
    ]
    
    if mime_type not in allowed_mimes:
        raise HTTPException(
            status_code=400, 
            detail="Invalid file type. Only binary executables are allowed."
        )
    
    # Validate filename
    safe_filename = os.path.basename(file.filename)
    if '..' in safe_filename or '/' in safe_filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    
    # Save uploaded file in secure manner
    upload_dir = os.getenv('UPLOAD_DIR', '/app/uploads')
    os.makedirs(upload_dir, exist_ok=True)
    
    # Create unique directory for this analysis
    analysis_dir = os.path.join(upload_dir, analysis_id)
    os.makedirs(analysis_dir, mode=0o755, exist_ok=True)
    
    file_path = os.path.join(analysis_dir, safe_filename)
    
    try:
        # Safely save file
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Set permissions
        os.chmod(file_path, 0o600)  # Read/write for owner only
        
        # Start analysis in background with Celery
        task = process_analysis.delay(
            analysis_id,
            file_path,
            analysis_request.dict(),
            current_user['user_id']
        )
        
        # Save analysis request
        db.execute("""
            INSERT INTO analysis_results
            (id, user_id, status, task_id, created_at)
            VALUES (?, ?, 'processing', ?, datetime('now'))
        """, (analysis_id, current_user['user_id'], task.id))
        
        return AnalysisResponse(
            analysis_id=analysis_id,
            status="processing",
            task_id=task.id
        )
    
    except Exception as e:
        logger.error(f"Error processing file: {e}")
        # Cleanup on error
        try:
            shutil.rmtree(analysis_dir, ignore_errors=True)
        except:
            pass
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/v1/analysis/{analysis_id}", response_model=AnalysisResponse)
@rate_limit(requests=60, window=60)  # 60 requests per minute
async def get_analysis_result(
    request: Request,
    analysis_id: str,
    current_user: Dict = Depends(get_current_user),
    db: Database = Depends(get_db)
):
    """Get analysis results"""
    # Validate UUID
    try:
        uuid.UUID(analysis_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid analysis ID format")
    
    result = db.execute(
        "SELECT * FROM analysis_results WHERE id = ? AND user_id = ?",
        (analysis_id, current_user['user_id'])
    ).fetchone()
    
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    response = AnalysisResponse(
        analysis_id=analysis_id,
        status=result['status'],
        task_id=result.get('task_id')
    )
    
    if result['status'] == 'completed':
        try:
            results = json.loads(result['results'])
            response.file_info = results.get('file_info')
            response.protections = results.get('protections')
            response.strings = results.get('strings')
            response.functions = results.get('functions')
            response.vulnerabilities = results.get('vulnerabilities')
            response.exploit_code = results.get('exploit_code')
            response.mitigations = results.get('mitigations')
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in results for analysis {analysis_id}")
            raise HTTPException(status_code=500, detail="Error parsing analysis results")
    
    return response

@app.get("/api/v1/analysis/{analysis_id}/status")
@rate_limit(requests=120, window=60)  # 120 requests per minute
async def get_analysis_status(
    request: Request,
    analysis_id: str,
    current_user: Dict = Depends(get_current_user),
    db: Database = Depends(get_db)
):
    """Get analysis status and progress"""
    # Validate UUID
    try:
        uuid.UUID(analysis_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid analysis ID format")
    
    result = db.execute(
        "SELECT status, task_id FROM analysis_results WHERE id = ? AND user_id = ?",
        (analysis_id, current_user['user_id'])
    ).fetchone()
    
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    if result['task_id']:
        task_result = process_analysis.AsyncResult(result['task_id'])
        return {
            "status": result['status'],
            "task_status": task_result.status,
            "progress": getattr(task_result, 'progress', None)
        }
    
    return {"status": result['status']}

@app.post("/api/v1/marketplace/list")
@rate_limit(requests=5, window=60)  # 5 requests per minute
async def list_exploit(
    request: Request,
    exploit_request: ExploitListingRequest,
    current_user: Dict = Depends(get_current_user),
    db: Database = Depends(get_db)
):
    """List an exploit in the marketplace"""
    if 'exploit_marketplace' not in current_user['features']:
        raise HTTPException(status_code=403, detail="Marketplace access not available")
    
    # Validar código do exploit (evitar injeção)
    if len(exploit_request.code) > 100000:  # 100KB máximo
        raise HTTPException(status_code=400, detail="Exploit code too large")
    
    marketplace = ExploitMarketplace(os.getenv("STRIPE_API_KEY"))
    
    # Create exploit listing
    exploit_data = {
        'title': exploit_request.title,
        'description': exploit_request.description,
        'type': exploit_request.exploit_type,
        'code': exploit_request.code
    }
    
    try:
        listing = marketplace.list_exploit(
            seller_id=current_user['user_id'],
            exploit_data=exploit_data,
            price=exploit_request.price
        )
        
        # Store in database
        db.execute("""
            INSERT INTO exploit_listings
            (user_id, product_id, price_id, title, description, type, price, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
        """, (
            current_user['user_id'],
            listing['product_id'],
            listing['price_id'],
            exploit_request.title,
            exploit_request.description,
            exploit_request.exploit_type,
            exploit_request.price
        ))
        
        return listing
    
    except Exception as e:
        logger.error(f"Error listing exploit: {e}")
        raise HTTPException(status_code=500, detail="Error listing exploit")

@app.get("/api/v1/usage/stats")
@rate_limit(requests=30, window=60)  # 30 requests per minute
async def get_usage_stats(
    request: Request,
    period_days: int = 30,
    current_user: Dict = Depends(get_current_user),
    db: Database = Depends(get_db)
):
    """Get user usage statistics"""
    if period_days < 1 or period_days > 365:
        raise HTTPException(status_code=400, detail="Period must be between 1 and 365 days")
    
    analytics = UsageAnalytics(db)
    return analytics.get_user_usage(current_user['user_id'], period_days)

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "2.0.0"
    }
    
    # Check database connection
    try:
        with get_db() as db:
            db.execute("SELECT 1")
        health_status["database"] = "connected"
    except Exception:
        health_status["database"] = "disconnected"
        health_status["status"] = "unhealthy"
    
    # Check Redis connection
    try:
        redis_client.ping()
        health_status["redis"] = "connected"
    except Exception:
        health_status["redis"] = "disconnected"
        health_status["status"] = "unhealthy"
    
    # Check Celery workers
    try:
        celery_inspect = process_analysis.control.inspect()
        if celery_inspect.active():
            health_status["celery"] = "connected"
        else:
            health_status["celery"] = "no workers"
            health_status["status"] = "unhealthy"
    except Exception:
        health_status["celery"] = "disconnected"
        health_status["status"] = "unhealthy"
    
    return health_status

# Error handlers
@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Global exception handler"""
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "request_id": getattr(request.state, 'request_id', None)
        }
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """HTTP exception handler"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "request_id": getattr(request.state, 'request_id', None)
        }
    )

# Webhook for Stripe
@app.post("/webhooks/stripe")
async def handle_stripe_webhook(
    request: Request,
    db: Database = Depends(get_db)
):
    """Handle Stripe webhooks for payment confirmation"""
    payload = await request.body()
    sig_header = request.headers.get('stripe-signature')
    
    try:
        # Verifica assinatura do webhook
        event = stripe.Webhook.construct_event(
            payload, sig_header, Config.STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")
    
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        
        # Update purchase status
        db.execute("""
            UPDATE purchases
            SET status = 'completed', completed_at = datetime('now')
            WHERE session_id = ?
        """, (session['id'],))
        
        # Grant access to buyer
        purchase = db.execute(
            "SELECT * FROM purchases WHERE session_id = ?",
            (session['id'],)
        ).fetchone()
        
        if purchase:
            db.execute("""
                INSERT INTO exploit_access
                (user_id, product_id, granted_at)
                VALUES (?, ?, datetime('now'))
            """, (purchase['user_id'], purchase['product_id']))
    
    return {"status": "success"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=8000,
        workers=Config.API_WORKERS,
        log_level=Config.LOG_LEVEL.lower()
    )
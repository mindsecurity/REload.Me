# api/rest_api.py
from fastapi import FastAPI, File, UploadFile, Depends, HTTPException, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict
import uuid
import os
import tempfile
import shutil
import logging
from concurrent.futures import ThreadPoolExecutor

from core.analyzer import BinaryAnalyzer
from core.exploit_gen import ExploitGenerator
from monetization.licensing import LicenseManager
from monetization.analytics import UsageAnalytics
from database import get_db, Database

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="REloadAI API",
    description="Automated binary analysis and exploit generation",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Initialize components
license_manager = LicenseManager(os.getenv("LICENSE_SECRET_KEY"))
exploit_generator = ExploitGenerator(os.getenv("OPENAI_API_KEY"))

# Thread pool for background tasks
executor = ThreadPoolExecutor(max_workers=5)

# Models
class AnalysisRequest(BaseModel):
    features: List[str] = ["basic_analysis", "string_extraction"]
    language: str = "python"
    generate_exploit: bool = False

class AnalysisResponse(BaseModel):
    analysis_id: str
    status: str
    file_info: Optional[Dict]
    protections: Optional[Dict]
    strings: Optional[List[Dict]]
    functions: Optional[List[Dict]]
    vulnerabilities: Optional[List[Dict]]
    exploit_code: Optional[str]
    mitigations: Optional[str]

class ExploitListingRequest(BaseModel):
    title: str
    description: str
    exploit_type: str
    code: str
    price: float
    test_binary: Optional[str]

# Dependency for authentication
async def get_current_user(
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
        
        return {
            'user_id': user['id'],
            'email': user['email'],
            'plan': license_info['plan'],
            'features': license_info['features'],
            'api_rate_limit': license_info['api_rate_limit']
        }
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

# Routes
@app.post("/api/v1/analyze", response_model=AnalysisResponse)
async def analyze_binary(
    file: UploadFile = File(...),
    request: AnalysisRequest = AnalysisRequest(),
    background_tasks: BackgroundTasks = None,
    current_user: Dict = Depends(get_current_user),
    db: Database = Depends(get_db)
):
    """Analyze a binary file"""
    analysis_id = str(uuid.uuid4())
    
    # Check if user has feature access
    for feature in request.features:
        if feature not in current_user['features']:
            raise HTTPException(
                status_code=403, 
                detail=f"Feature '{feature}' not available in your plan"
            )
    
    # Save uploaded file
    temp_dir = tempfile.mkdtemp()
    file_path = os.path.join(temp_dir, file.filename)
    
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Start analysis in background
        background_tasks.add_task(
            process_analysis,
            analysis_id,
            file_path,
            request,
            current_user['user_id'],
            db
        )
        
        return AnalysisResponse(
            analysis_id=analysis_id,
            status="processing"
        )
    
    except Exception as e:
        logger.error(f"Error processing file: {e}")
        shutil.rmtree(temp_dir)
        raise HTTPException(status_code=500, detail=str(e))

def process_analysis(analysis_id: str, file_path: str, request: AnalysisRequest, user_id: str, db: Database):
    """Process binary analysis in background"""
    try:
        analyzer = BinaryAnalyzer(file_path)
        analyzer.connect()
        
        results = {}
        
        # Perform requested analyses
        if "basic_analysis" in request.features:
            results['file_info'] = analyzer.get_file_info()
            results['protections'] = analyzer.analyze_protections()
        
        if "string_extraction" in request.features:
            results['strings'] = analyzer.extract_strings()
        
        if "function_analysis" in request.features:
            results['functions'] = analyzer.analyze_functions()
            
            # Extract vulnerabilities
            vulnerabilities = []
            for func in results['functions']:
                if func.get('vulnerabilities'):
                    vulnerabilities.extend(func['vulnerabilities'])
            results['vulnerabilities'] = vulnerabilities
        
        # Generate exploit if requested
        if request.generate_exploit and vulnerabilities:
            main_func = analyzer.get_main_function()
            if main_func:
                main_disasm = analyzer.get_disassembly(main_func['offset'])
                
                # Generate exploit for first vulnerability
                results['exploit_code'] = exploit_generator.generate_exploit(
                    vulnerabilities[0],
                    main_disasm,
                    request.language
                )
                
                # Generate mitigations
                results['mitigations'] = exploit_generator.suggest_mitigations(
                    vulnerabilities[0]
                )
        
        analyzer.close()
        
        # Update database
        db.execute("""
            INSERT INTO analysis_results
            (id, user_id, status, results, created_at)
            VALUES (?, ?, 'completed', ?, datetime('now'))
        """, (analysis_id, user_id, json.dumps(results)))
        
        # Track usage
        analytics = UsageAnalytics(db)
        analytics.track_analysis(
            user_id=user_id,
            analysis_type="binary_analysis",
            binary_size=os.path.getsize(file_path),
            duration_seconds=0,  # You'd track actual duration
            success=True,
            features_used=request.features
        )
        
        # Cleanup
        shutil.rmtree(os.path.dirname(file_path))
        
    except Exception as e:
        logger.error(f"Error in analysis {analysis_id}: {e}")
        db.execute("""
            UPDATE analysis_results
            SET status = 'failed', error = ?
            WHERE id = ?
        """, (str(e), analysis_id))

@app.get("/api/v1/analysis/{analysis_id}", response_model=AnalysisResponse)
async def get_analysis_result(
    analysis_id: str,
    current_user: Dict = Depends(get_current_user),
    db: Database = Depends(get_db)
):
    """Get analysis results"""
    result = db.execute(
        "SELECT * FROM analysis_results WHERE id = ? AND user_id = ?",
        (analysis_id, current_user['user_id'])
    ).fetchone()
    
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    response = AnalysisResponse(
        analysis_id=analysis_id,
        status=result['status']
    )
    
    if result['status'] == 'completed':
        results = json.loads(result['results'])
        response.file_info = results.get('file_info')
        response.protections = results.get('protections')
        response.strings = results.get('strings')
        response.functions = results.get('functions')
        response.vulnerabilities = results.get('vulnerabilities')
        response.exploit_code = results.get('exploit_code')
        response.mitigations = results.get('mitigations')
    
    return response

@app.post("/api/v1/marketplace/list")
async def list_exploit(
    request: ExploitListingRequest,
    current_user: Dict = Depends(get_current_user),
    db: Database = Depends(get_db)
):
    """List an exploit in the marketplace"""
    if 'exploit_marketplace' not in current_user['features']:
        raise HTTPException(status_code=403, detail="Marketplace access not available")
    
    marketplace = ExploitMarketplace(os.getenv("STRIPE_API_KEY"))
    
    # Create exploit listing
    exploit_data = {
        'title': request.title,
        'description': request.description,
        'type': request.exploit_type,
        'code': request.code
    }
    
    listing = marketplace.list_exploit(
        seller_id=current_user['user_id'],
        exploit_data=exploit_data,
        price=request.price
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
        request.title,
        request.description,
        request.exploit_type,
        request.price
    ))
    
    return listing

@app.get("/api/v1/marketplace/exploits")
async def browse_exploits(
    type: Optional[str] = None,
    min_price: Optional[float] = None,
    max_price: Optional[float] = None,
    db: Database = Depends(get_db)
):
    """Browse available exploits"""
    query = "SELECT * FROM exploit_listings WHERE status = 'active'"
    params = []
    
    if type:
        query += " AND type = ?"
        params.append(type)
    
    if min_price is not None:
        query += " AND price >= ?"
        params.append(min_price)
    
    if max_price is not None:
        query += " AND price <= ?"
        params.append(max_price)
    
    exploits = db.execute(query, params).fetchall()
    
    return [dict(row) for row in exploits]

@app.post("/api/v1/marketplace/purchase/{product_id}")
async def purchase_exploit(
    product_id: str,
    current_user: Dict = Depends(get_current_user),
    db: Database = Depends(get_db)
):
    """Purchase an exploit from the marketplace"""
    # Get listing
    listing = db.execute(
        "SELECT * FROM exploit_listings WHERE product_id = ?",
        (product_id,)
    ).fetchone()
    
    if not listing:
        raise HTTPException(status_code=404, detail="Exploit not found")
    
    marketplace = ExploitMarketplace(os.getenv("STRIPE_API_KEY"))
    
    # Create checkout session
    checkout = marketplace.purchase_exploit(
        buyer_id=current_user['user_id'],
        product_id=product_id,
        price_id=listing['price_id']
    )
    
    # Store purchase intent
    db.execute("""
        INSERT INTO purchases
        (user_id, product_id, session_id, status, created_at)
        VALUES (?, ?, ?, 'pending', datetime('now'))
    """, (current_user['user_id'], product_id, checkout['session_id']))
    
    return checkout

@app.get("/api/v1/usage/stats")
async def get_usage_stats(
    period_days: int = 30,
    current_user: Dict = Depends(get_current_user),
    db: Database = Depends(get_db)
):
    """Get user usage statistics"""
    analytics = UsageAnalytics(db)
    return analytics.get_user_usage(current_user['user_id'], period_days)

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy"}

# Webhook for Stripe
@app.post("/webhooks/stripe")
async def handle_stripe_webhook(
    payload: Dict,
    db: Database = Depends(get_db)
):
    """Handle Stripe webhooks for payment confirmation"""
    # In production, verify webhook signature
    event = payload
    
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
    uvicorn.run(app, host="0.0.0.0", port=8000)
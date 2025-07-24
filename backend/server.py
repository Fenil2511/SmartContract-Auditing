from fastapi import FastAPI, APIRouter, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional
import uuid
from datetime import datetime
from audit_engine import SolidityAuditor

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Initialize the audit engine
auditor = SolidityAuditor()

# Define Models
class ContractAnalysisRequest(BaseModel):
    contract_code: str
    filename: Optional[str] = None

class ContractAnalysisResponse(BaseModel):
    id: str
    summary: dict
    vulnerabilities: List[dict]
    recommendations: List[dict]
    timestamp: datetime

class AuditHistory(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    contract_code: str
    filename: Optional[str] = None
    analysis_result: dict
    timestamp: datetime = Field(default_factory=datetime.utcnow)

# API Routes
@api_router.get("/")
async def root():
    return {"message": "Smart Contract Auditing Toolkit API"}

@api_router.post("/analyze", response_model=dict)
async def analyze_contract(request: ContractAnalysisRequest):
    """Analyze a Solidity contract for vulnerabilities"""
    try:
        if not request.contract_code.strip():
            raise HTTPException(status_code=400, detail="Contract code cannot be empty")
        
        # Perform the analysis
        analysis_result = auditor.analyze_contract(request.contract_code)
        
        # Save to database
        audit_record = AuditHistory(
            contract_code=request.contract_code,
            filename=request.filename,
            analysis_result=analysis_result
        )
        
        await db.audit_history.insert_one(audit_record.dict())
        
        # Return the analysis result with additional metadata
        return {
            "id": audit_record.id,
            "summary": analysis_result["summary"],
            "vulnerabilities": analysis_result["vulnerabilities"],
            "recommendations": analysis_result["recommendations"],
            "timestamp": audit_record.timestamp.isoformat(),
            "filename": request.filename
        }
        
    except Exception as e:
        logging.error(f"Error analyzing contract: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@api_router.post("/analyze-file")
async def analyze_contract_file(file: UploadFile = File(...)):
    """Analyze a Solidity file upload"""
    try:
        if not file.filename.endswith('.sol'):
            raise HTTPException(status_code=400, detail="Only .sol files are supported")
        
        # Read file content
        contract_code = await file.read()
        contract_code = contract_code.decode('utf-8')
        
        # Perform analysis
        analysis_result = auditor.analyze_contract(contract_code)
        
        # Save to database
        audit_record = AuditHistory(
            contract_code=contract_code,
            filename=file.filename,
            analysis_result=analysis_result
        )
        
        await db.audit_history.insert_one(audit_record.dict())
        
        return {
            "id": audit_record.id,
            "summary": analysis_result["summary"],
            "vulnerabilities": analysis_result["vulnerabilities"],
            "recommendations": analysis_result["recommendations"],
            "timestamp": audit_record.timestamp.isoformat(),
            "filename": file.filename
        }
        
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File encoding not supported. Please use UTF-8.")
    except Exception as e:
        logging.error(f"Error analyzing file: {str(e)}")
        raise HTTPException(status_code=500, detail=f"File analysis failed: {str(e)}")

@api_router.get("/history")
async def get_audit_history(limit: int = 10):
    """Get audit history"""
    try:
        history = await db.audit_history.find().sort("timestamp", -1).limit(limit).to_list(limit)
        
        # Format response
        formatted_history = []
        for record in history:
            formatted_history.append({
                "id": record["id"],
                "filename": record.get("filename", "Untitled"),
                "timestamp": record["timestamp"].isoformat(),
                "summary": record["analysis_result"]["summary"],
                "vulnerabilities_count": len(record["analysis_result"]["vulnerabilities"])
            })
        
        return {"history": formatted_history}
        
    except Exception as e:
        logging.error(f"Error fetching history: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch audit history")

@api_router.get("/history/{audit_id}")
async def get_audit_details(audit_id: str):
    """Get detailed audit results by ID"""
    try:
        record = await db.audit_history.find_one({"id": audit_id})
        
        if not record:
            raise HTTPException(status_code=404, detail="Audit record not found")
        
        return {
            "id": record["id"],
            "contract_code": record["contract_code"],
            "filename": record.get("filename", "Untitled"),
            "summary": record["analysis_result"]["summary"],
            "vulnerabilities": record["analysis_result"]["vulnerabilities"],
            "recommendations": record["analysis_result"]["recommendations"],
            "timestamp": record["timestamp"].isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error fetching audit details: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch audit details")

@api_router.get("/stats")
async def get_audit_stats():
    """Get audit statistics"""
    try:
        total_audits = await db.audit_history.count_documents({})
        
        # Get recent audits for stats
        recent_audits = await db.audit_history.find().limit(100).to_list(100)
        
        total_vulnerabilities = 0
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for audit in recent_audits:
            vulnerabilities = audit["analysis_result"]["vulnerabilities"]
            total_vulnerabilities += len(vulnerabilities)
            
            for vuln in vulnerabilities:
                severity = vuln["severity"].lower()
                if severity == "critical":
                    critical_count += 1
                elif severity == "high":
                    high_count += 1
                elif severity == "medium":
                    medium_count += 1
                elif severity == "low":
                    low_count += 1
        
        return {
            "total_audits": total_audits,
            "total_vulnerabilities": total_vulnerabilities,
            "vulnerability_breakdown": {
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count
            },
            "average_vulnerabilities_per_audit": round(total_vulnerabilities / max(len(recent_audits), 1), 2)
        }
        
    except Exception as e:
        logging.error(f"Error fetching stats: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch statistics")

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
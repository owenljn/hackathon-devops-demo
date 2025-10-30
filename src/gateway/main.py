# AutoMCP IaC Security Demo - FastAPI Gateway

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import logging
import os
from dotenv import load_dotenv

from .routes_github import router as github_router
from .routes_slack import router as slack_router

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="AutoMCP IaC Security Demo",
    description="Automated IaC security scanning and fixing pipeline",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(github_router, prefix="/webhook", tags=["webhooks"])
app.include_router(slack_router, prefix="", tags=["slack"])

@app.get("/healthz", summary="Health Check")
async def health_check():
    """Health check endpoint for load balancers and monitoring"""
    return {
        "status": "healthy",
        "service": "automcp-demo",
        "version": "1.0.0"
    }

@app.get("/", summary="Root Endpoint")
async def root():
    """Root endpoint with service information"""
    return {
        "service": "AutoMCP IaC Security Demo",
        "description": "Webhook gateway for automated IaC security scanning",
        "endpoints": {
            "health": "/healthz",
            "webhook": "/webhook/github"
        }
    }

# Startup event
@app.on_event("startup")
async def startup_event():
    """Validate environment and initialize MCP tools on startup"""
    required_vars = ["SLACK_WEBHOOK_URL", "GITHUB_TOKEN", "GITHUB_REPO"]

    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        logger.warning(f"Missing environment variables: {missing_vars}")
        logger.warning("Some features may not work without configuration")

    # Register MCP tools
    from src.mcp.orchestrator import register_tools
    register_tools()

    logger.info("AutoMCP IaC Security Demo started successfully")

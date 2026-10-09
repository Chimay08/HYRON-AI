from fastapi import APIRouter, Depends, HTTPException, status

from schemas.scan_result import GraphData
from services.pipeline import STORE
from services.security import workspace_id

router = APIRouter(prefix="/api", tags=["graph"])


@router.get("/graph/{scan_id}", response_model=GraphData)
async def get_graph(scan_id: str, workspace: str = Depends(workspace_id)):
    """Cytoscape-ready nodes (projects + packages with status, ecosystem, version, risk) and dependency edges."""
    entry = STORE.get(workspace, scan_id)
    if entry is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found (results are kept in memory and lost on restart)")
    if entry.graph is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Website inspections have no dependency graph")
    return entry.graph

from fastapi import APIRouter, Depends, HTTPException

from schemas.scan_result import RepositoryInfo, RepositoryRequest
from services import github_service
from services.security import scan_rate_limit

router = APIRouter(prefix="/api/repositories", tags=["repositories"])


@router.post("/validate", response_model=RepositoryInfo, dependencies=[Depends(scan_rate_limit)])
async def validate_repository(body: RepositoryRequest):
    """Check a GitHub URL and access before scanning.

    Returns visibility, branches, the commit that would be scanned and the supported dependency files found.
    Credentials are never returned; `auth` only says whether a server-side token was used.
    """
    try:
        return await github_service.inspect_repository(body.url, body.branch)
    except github_service.GitHubError as exc:
        raise HTTPException(exc.status, exc.message) from exc

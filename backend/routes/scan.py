from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status

from schemas.scan_result import (
    DataSource, ParseIssue, RepositoryRequest, ScanListItem, ScanReport, ScanSource, WebsiteReport, WebsiteRequest,
)
from services import github_service, website_inspector
from services.manifest_parser import SUPPORTED_HELP, detect_kind, max_bytes_for, parse_dependency_tree, parse_files
from services.osv_service import now_iso
from services.pipeline import list_items, load_demo_data, run_scan, store_website_report
from services.security import scan_rate_limit, workspace_id

router = APIRouter(prefix="/api", tags=["scan"])

MAX_FILES = 10


def _no_projects(issues: list[ParseIssue], message: str = "No file could be parsed") -> HTTPException:
    return HTTPException(
        status.HTTP_422_UNPROCESSABLE_CONTENT,
        {"message": message, "issues": [i.model_dump() for i in issues]},
    )


def _require_dependencies(projects, issues: list[ParseIssue]) -> None:
    """An input with no dependencies has nothing to check. Reporting it as a completed
    scan would read as "no vulnerabilities found", so reject it explicitly."""
    if not any(p.dependencies for p in projects):
        raise _no_projects(
            issues, "No dependencies were found in the input, so nothing could be checked. "
                    "Upload a manifest or lockfile that lists dependencies",
        )


@router.post("/scan", response_model=ScanReport, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(scan_rate_limit)])
async def scan_uploads(
    files: list[UploadFile] = File(..., description=SUPPORTED_HELP),
    workspace: str = Depends(workspace_id),
):
    """Upload dependency manifests / lockfiles and run a live scan (OSV.dev + CISA KEV + FIRST EPSS).

    Files are parsed as data only and never executed. Max 10 files; 1 MB per manifest, 5 MB per lockfile.
    A lockfile and its manifest in the same upload are paired (the lockfile supplies resolved versions).
    """
    if len(files) > MAX_FILES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"At most {MAX_FILES} files per scan")
    collected: list[tuple[str, bytes]] = []
    for upload in files:
        filename = (upload.filename or "upload").replace("\\", "/").split("/")[-1]
        if detect_kind(filename) is None:
            raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, f"{filename}: unsupported file type. {SUPPORTED_HELP}")
        limit = max_bytes_for(filename)
        content = await upload.read(limit + 1)
        if len(content) > limit:
            raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, f"{filename}: larger than {limit // 1000} KB")
        collected.append((filename, content))

    projects, issues = parse_files(collected)
    if not projects:
        raise _no_projects(issues)
    _require_dependencies(projects, issues)
    source = ScanSource(type="upload", label=", ".join(n for n, _ in collected), files=[n for n, _ in collected])
    report, _ = await run_scan(projects, mode="live", source=source, workspace=workspace, parse_issues=issues)
    return report


@router.post("/scan/repository", response_model=ScanReport, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(scan_rate_limit)])
async def scan_repository(body: RepositoryRequest, workspace: str = Depends(workspace_id)):
    """Scan a GitHub repository: fetch its manifests/lockfiles at the branch head commit, then run a live scan.

    Public repositories work without credentials. Private repositories require a server-side GITHUB_TOKEN.
    """
    try:
        info = await github_service.inspect_repository(body.url, body.branch)
        if not info.manifests:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                {"message": f"No supported dependency files found in {info.full_name}@{info.branch}. {SUPPORTED_HELP}.",
                 "issues": []},
            )
        files = await github_service.fetch_manifests(info)
    except github_service.GitHubError as exc:
        raise HTTPException(exc.status, exc.message) from exc

    projects, issues = parse_files(files)
    issues += [ParseIssue(file=s, message="skipped", level="info") for s in info.skipped]
    if info.truncated:
        issues.append(ParseIssue(file=info.full_name, message="GitHub truncated the file tree; some manifests may be missing"))
    if not projects:
        raise _no_projects(issues, "Dependency files were found but none could be parsed")
    _require_dependencies(projects, issues)
    source = ScanSource(
        type="repository", label=info.full_name, url=info.html_url, branch=info.branch,
        commit=info.commit, files=info.manifests, private=info.private,
    )
    github_src = DataSource(
        name="GitHub API", url=f"{info.html_url}/tree/{info.commit}", status="ok", retrieved_at=now_iso(),
        detail=f"{len(files)} file(s) read at commit {info.commit[:10]} ({info.auth} access)",
    )
    report, _ = await run_scan(projects, mode="live", source=source, workspace=workspace,
                               parse_issues=issues, extra_sources=[github_src])
    return report


@router.post("/scan/website", response_model=WebsiteReport, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(scan_rate_limit)])
async def scan_website(body: WebsiteRequest, workspace: str = Depends(workspace_id)):
    """Passive, read-only inspection of one public page.

    Reports detected technologies and *potential* exposures (library versions seen in public asset URLs that
    match OSV advisories). It never reports confirmed package vulnerabilities and performs no active testing.
    """
    if not body.acknowledge_passive:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "Confirm that this is a passive inspection of a public page (acknowledge_passive=true).",
        )
    try:
        report = await website_inspector.inspect_website(body.url)
    except website_inspector.WebsiteError as exc:
        raise HTTPException(exc.status, exc.message) from exc
    store_website_report(workspace, report)
    return report


@router.post("/demo", response_model=ScanReport, status_code=status.HTTP_201_CREATED)
async def run_demo(workspace: str = Depends(workspace_id)):
    """Run the bundled SIMULATED demo scenario. Works offline without any credentials."""
    data = load_demo_data()
    issues: list[ParseIssue] = []
    projects = parse_dependency_tree(data, "demo_dependencies.json", issues)
    source = ScanSource(type="demo", label="Demo scenario (simulated)", files=["demo_dependencies.json"])
    report, _ = await run_scan(projects, mode="demo", source=source, workspace=workspace,
                               parse_issues=issues, demo_data=data)
    return report


@router.get("/scans", response_model=list[ScanListItem])
async def scan_history(workspace: str = Depends(workspace_id)):
    """Scan history for this workspace (newest first). In-memory: cleared when the server restarts."""
    return list_items(workspace)

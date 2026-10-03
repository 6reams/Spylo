import asyncio
import json
import random
import re
import ssl
from pathlib import Path
from typing import Dict, List, Optional

import aiohttp
import certifi
from aiohttp import ClientResponse
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.box import SQUARE

# Modern minimal color scheme
PRIMARY_BLUE = "#0066cc"  # Deeper blue for main elements
SECONDARY_BLUE = "#4d94ff"  # Lighter blue for secondary elements
WHITE = "#ffffff"  # Pure white

console = Console()

SITES_PATH = Path(__file__).resolve().parent.parent / "data" / "sites.json"

DEFAULT_HEADERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.2 Mobile/15E148 Safari/604.1",
]


class UsernameScanner:
    def __init__(
        self,
        timeout: int = 15,
        concurrency: int = 50,
        retries: int = 2,
        proxy: Optional[str] = None,
        verify_tls: bool = True,
    ):
        self.timeout = timeout
        self.concurrency = concurrency
        self.retries = retries
        self.proxy = proxy
        self.verify_tls = verify_tls
        with open(SITES_PATH, "r", encoding="utf-8") as f:
            self.sites: Dict[str, dict] = json.load(f)

    def _ssl_option(self):
        """Return the aiohttp `ssl` argument for this scanner.

        Verification is on by default; `False` disables it entirely and is
        only reachable through the explicit `verify_tls` opt-out.
        """
        if not self.verify_tls:
            return False
        return ssl.create_default_context(cafile=certifi.where())

    def scan(self, username: str) -> dict:
        try:
            # Show scan initialization
            console.print(f"[{PRIMARY_BLUE}]Starting scan for[/{PRIMARY_BLUE}] [{SECONDARY_BLUE}]{username}[/{SECONDARY_BLUE}]")
            if not self.verify_tls:
                console.print("[yellow]Warning: TLS certificate verification is disabled[/yellow]")
            console.print()

            results = asyncio.run(self._scan_async(username))
            found_accounts = [r for r in results if r is not None and not r.get("error")]
            failed_sites = [r["site"] for r in results if r is not None and r.get("error")]
            
            total = len(self.sites)
            summary = {
                "username": username,
                "total_checked": total,
                "found": len(found_accounts),
                "failed": len(failed_sites),
                "success_rate": f"{(len(found_accounts) / total) * 100:.1f}%" if total else "0.0%"
            }
            
            if found_accounts:
                console.print()
                console.print(f"[{PRIMARY_BLUE}]Found {len(found_accounts)} accounts:[/{PRIMARY_BLUE}]")
                for account in found_accounts:
                    console.print(f"[{SECONDARY_BLUE}]\u2022 {account['site']}:[/{SECONDARY_BLUE}] {account['url']}")
            
            console.print()
            console.print(f"[{PRIMARY_BLUE}]Scan Summary:[/{PRIMARY_BLUE}]")
            console.print(f"[{SECONDARY_BLUE}]\u2022 Total Sites:[/{SECONDARY_BLUE}] {summary['total_checked']}")
            console.print(f"[{SECONDARY_BLUE}]\u2022 Found:[/{SECONDARY_BLUE}] {summary['found']}")
            console.print(f"[{SECONDARY_BLUE}]\u2022 Success Rate:[/{SECONDARY_BLUE}] {summary['success_rate']}")
            console.print()
            
            return {
                "accounts": found_accounts,
                "summary": summary,
                "failed_sites": failed_sites
            }
        except Exception as e:
            console.print(f"[{PRIMARY_BLUE}]Error during scan: {str(e)}[/{PRIMARY_BLUE}]")
            return {
                "error": str(e),
                "accounts": [],
                "summary": {"username": username, "total_checked": 0, "found": 0, "failed": 0}
            }

    async def _scan_async(self, username: str) -> List[dict]:
        sem = asyncio.Semaphore(self.concurrency)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        connector = aiohttp.TCPConnector(ssl=self._ssl_option())
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            tasks = []
            for site, cfg in self.sites.items():
                tasks.append(self._probe_site(sem, session, site, cfg, username))
            
            results = []
            total_sites = len(tasks)
            completed = 0
            found = 0
            
            with Progress(
                "{task.description}",
                SpinnerColumn(),
                "[",
                TimeElapsedColumn(),
                "] ",
                "•",
                "[progress.percentage]{task.percentage:>3.0f}%",
                console=console,
                transient=False,
                expand=True
            ) as progress:
                scan_task = progress.add_task(
                    "starting...",
                    total=total_sites
                )
                
                for coro in asyncio.as_completed(tasks):
                    res = await coro
                    completed += 1
                    
                    if res:
                        if res.get("error"):
                            # Skip displaying errors to maintain clean output
                            pass
                        else:
                            found += 1
                            console.print(Panel(
                                f"[{SECONDARY_BLUE}]{res['site']}[/{SECONDARY_BLUE}]\n[{WHITE}]{res['url']}[/{WHITE}]",
                                title="[white]Found Account[/white]",
                                box=SQUARE,
                                style=f"{WHITE}",
                                padding=(0, 2)
                            ))
                        results.append(res)
                    
                    # Update progress description
                    progress.update(
                        scan_task,
                        advance=1,
                        description=f"[{WHITE}]{found} accounts found[/{WHITE}]"
                    )
            
            return results

    async def _probe_site(self, sem, session: aiohttp.ClientSession, site: str, cfg: dict, username: str):
        url = cfg.get("url", "").replace("{account}", username)
        error_type = cfg.get("errorType", "status_code")
        error_msg = cfg.get("errorMsg")
        request_head_only = cfg.get("request_head_only", False)
        headers = {"User-Agent": random.choice(DEFAULT_HEADERS)}
        if cfg.get("headers"):
            headers.update(cfg["headers"])  # allow site-specific headers

        try:
            async with sem:
                for attempt in range(self.retries + 1):
                    try:
                        method = session.head if request_head_only else session.get
                        async with method(url, proxy=self.proxy, headers=headers, allow_redirects=True) as resp:
                            if await self._is_hit(resp, error_type, error_msg):
                                return {
                                    "site": site,
                                    "url": str(resp.url),
                                    "status": "FOUND",
                                    "status_code": resp.status
                                }
                            return None
                    except (asyncio.TimeoutError, aiohttp.ClientError):
                        if attempt == self.retries:
                            raise
                        await asyncio.sleep(1)
                return None
        except asyncio.TimeoutError:
            return {
                "site": site,
                "error": "Timeout",
                "status": "ERROR"
            }
        except aiohttp.ClientError as e:
            return {
                "site": site,
                "error": f"Connection error: {str(e)}",
                "status": "ERROR"
            }
        except Exception as e:
            return {
                "site": site,
                "error": f"Unexpected error: {str(e)}",
                "status": "ERROR"
            }

    async def _is_hit(self, resp: ClientResponse, error_type: str, error_msg: Optional[str]) -> bool:
        # Sherlock-style detection rules with enhancements
        status = resp.status
        text = None
        if error_type in {"message", "regex"}:
            # read text only when necessary to save time
            text = await resp.text(errors="ignore")

        if error_type == "status_code":
            return status == 200
        if error_type == "message":
            # if error message NOT present, assume account exists
            return bool(error_msg) and error_msg not in (text or "")
        if error_type == "response_url":
            return str(resp.url) == str(resp.request_info.url)
        if error_type == "regex":
            if not error_msg:
                return status == 200
            return re.search(error_msg, text or "", re.I) is not None
        # fallback
        return status == 200

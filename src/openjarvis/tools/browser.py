"""Browser automation tools — Playwright-based web interaction."""

from __future__ import annotations

import atexit
import base64
import concurrent.futures
import json
import threading
import uuid
from functools import wraps
from typing import Any

from openjarvis.core.execution import ExecutionState, ToolEffect
from openjarvis.core.registry import ToolRegistry
from openjarvis.core.types import ToolResult
from openjarvis.tools._stubs import BaseTool, ToolSpec, _BoundedToolRunner


class BrowserActionError(RuntimeError):
    def __init__(self, failure: str, detail: str, *, dispatched: bool = False):
        super().__init__(f"{failure}: {detail}")
        self.failure = failure
        self.state = (
            ExecutionState.UNKNOWN_OUTCOME if dispatched else ExecutionState.NOT_STARTED
        )


def _browser_operation(get_session):
    """Keep all synchronous Playwright operations on one owning thread."""

    def decorate(method):
        @wraps(method)
        def execute(self, **params):
            try:
                result = get_session().run(lambda: method(self, **params))
                if result.success and self.tool_id in {
                    "browser_navigate",
                    "browser_extract",
                    "browser_axtree",
                }:
                    # Agent tool messages carry content, not ToolResult metadata.
                    # Keep identity evidence visible even when page text is clipped.
                    observation = {
                        "document_id": result.metadata["document_id"],
                        "targets": result.metadata.get("targets", []),
                    }
                    result.content = (
                        "[Browser observation data] "
                        + json.dumps(observation)
                        + "\n\n"
                        + result.content
                    )
                return result
            except Exception as exc:
                return ToolResult(
                    self.tool_id,
                    f"Browser execution error: {exc}",
                    success=False,
                    execution_state=(
                        exc.state
                        if isinstance(exc, BrowserActionError)
                        else ExecutionState.UNKNOWN_OUTCOME
                    ),
                )

        return execute

    return decorate


class _BrowserSession:
    """Manages a shared Playwright browser session (lazy init)."""

    def __init__(self) -> None:
        self._playwright = None
        self._browser = None
        self._page = None
        self._context = None
        self._browser_thread = None
        self._owner_thread = None
        self._document_id = uuid.uuid4().hex
        self._observed_targets = []
        self._runner = _BoundedToolRunner(1, 8, name_prefix="openjarvis-browser")
        atexit.register(self._runner.shutdown)

    def run(self, function):
        if self._owner_thread == threading.get_ident():
            return function()

        def owned():
            self._owner_thread = threading.get_ident()
            return function()

        future = self._runner.submit(owned)
        if future is None:
            raise BrowserActionError("CAPACITY", "Browser queue is full")
        try:
            return future.result(timeout=25)
        except concurrent.futures.TimeoutError:
            cancelled = future.cancel()
            raise BrowserActionError(
                "TIMEOUT" if cancelled else "UNKNOWN_OUTCOME",
                "Browser operation timed out",
                dispatched=not cancelled,
            )

    @property
    def document_id(self) -> str:
        return self._document_id

    def _invalidate_document(self, *_args) -> None:
        # Conservatively invalidate even on same-URL reloads or iframe changes.
        self._document_id = uuid.uuid4().hex
        self._observed_targets = []

    def observe_targets(self) -> list[dict[str, Any]]:
        """Capture visible DOM identity, independent of text/selector identity."""
        page = self.page
        self._observed_targets = []
        targets = []
        for frame in page.frames:
            handles = frame.locator(
                "button,a[href],input,textarea,select,[role=button],[role=link],"
                "[contenteditable=true]"
            ).element_handles()
            for handle in handles:
                if len(targets) >= 100:
                    return targets
                if not handle.is_visible() or not handle.is_enabled():
                    continue
                description = handle.evaluate("""el => ({
                    tag: el.tagName.toLowerCase(),
                    id: el.id.length <= 256 ? el.id : '',
                    type: el.getAttribute('type') || '',
                    name: (el.getAttribute('aria-label') || el.innerText ||
                           el.getAttribute('placeholder') || el.id || '').slice(0, 160)
                })""")
                self._observed_targets.append(handle)
                targets.append({**description, "frame_url": frame.url})
        return targets

    def require_observed_target(self, handle) -> None:
        for observed in self._observed_targets:
            try:
                if handle.evaluate(
                    "(element, observed) => element === observed", observed
                ):
                    return
            except Exception:
                # Different frame or a detached/disposed observed handle
                # cannot prove identity. Never resolve by matching its text.
                continue
        raise BrowserActionError(
            "STALE_TARGET",
            "DOM target was not in the latest observation; observe again",
        )

    def require_document(self, expected: str) -> None:
        if not isinstance(expected, str) or expected != self._document_id:
            raise BrowserActionError(
                "STALE_TARGET",
                "Observe the page again and supply its document_id",
            )

    def _ensure_browser(self) -> None:
        if self._page is not None:
            if self._browser_thread not in (None, threading.get_ident()):
                raise RuntimeError("Browser accessed outside its owning thread")
            return
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise ImportError(
                "playwright not installed. Install with: uv sync --extra browser"
            )
        self._playwright = sync_playwright().start()
        self._browser = self._playwright.chromium.launch(headless=True)
        self._context = self._browser.new_context(service_workers="block")
        self._context.route("**/*", self._guard_request)
        self._page = self._context.new_page()
        self._browser_thread = threading.get_ident()
        self._page.set_default_timeout(8000)
        self._page.on("framenavigated", self._invalidate_document)
        self._invalidate_document()

    @staticmethod
    def _guard_request(route) -> None:
        from openjarvis.security.ssrf import check_ssrf

        try:
            error = check_ssrf(route.request.url)
        except Exception:
            error = "Request guard failed"
        if error:
            route.abort("blockedbyclient")
        else:
            route.continue_()

    @property
    def page(self):
        self._ensure_browser()
        return self._page

    def close(self) -> None:
        if self._browser_thread is not None:
            return self.run(self._close)
        self._close()

    def _close(self) -> None:
        if self._browser:
            self._browser.close()
        if self._playwright:
            self._playwright.stop()
        self._playwright = self._browser = self._page = None
        self._context = self._browser_thread = None
        self._invalidate_document()


_session = _BrowserSession()


# ---------------------------------------------------------------------------
# Tool 1: BrowserNavigateTool
# ---------------------------------------------------------------------------


@ToolRegistry.register("browser_navigate")
class BrowserNavigateTool(BaseTool):
    """Navigate to a URL in the browser."""

    tool_id = "browser_navigate"
    is_local = False

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name="browser_navigate",
            description=(
                "Navigate to a URL in the browser."
                " Returns the page title and text content."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL to navigate to.",
                    },
                    "wait_for": {
                        "type": "string",
                        "description": (
                            "Wait condition: 'load', 'domcontentloaded',"
                            " or 'networkidle'. Default: 'load'."
                        ),
                    },
                },
                "required": ["url"],
            },
            category="browser",
            required_capabilities=["network:fetch"],
            effect=ToolEffect.READ_ONLY,
        )

    @_browser_operation(lambda: _session)
    def execute(self, **params: Any) -> ToolResult:
        url = params.get("url", "")
        if not url:
            return ToolResult(
                tool_name="browser_navigate",
                content="No URL provided.",
                success=False,
            )

        wait_for = params.get("wait_for", "load")
        if wait_for not in ("load", "domcontentloaded", "networkidle"):
            wait_for = "load"

        # SSRF check — never skipped. check_ssrf falls back to a pure-Python
        # implementation when the Rust backend is unavailable, so an
        # uncompiled extension must not silently disable SSRF protection.
        from openjarvis.security.ssrf import check_ssrf

        ssrf_error = check_ssrf(url)
        if ssrf_error:
            return ToolResult(
                tool_name="browser_navigate",
                content=f"SSRF blocked: {ssrf_error}",
                success=False,
            )

        try:
            page = _session.page
            response = page.goto(url, wait_until=wait_for)
            title = page.title()
            text_content = page.inner_text("body")
            if len(text_content) > 5000:
                text_content = text_content[:5000] + "\n\n[Content truncated]"

            status = response.status if response else None
            return ToolResult(
                tool_name="browser_navigate",
                content=f"Title: {title}\n\n{text_content}",
                success=status is None or status < 400,
                metadata={
                    "url": page.url,
                    "title": title,
                    "status": status,
                    "document_id": _session.document_id,
                    "targets": _session.observe_targets(),
                },
                execution_state=ExecutionState.EXECUTED,
            )
        except ImportError:
            return ToolResult(
                tool_name="browser_navigate",
                content=(
                    "playwright not installed. Install with: uv sync --extra browser"
                ),
                success=False,
            )
        except Exception as exc:
            return ToolResult(
                tool_name="browser_navigate",
                content=f"Navigation error: {exc}",
                success=False,
            )


# ---------------------------------------------------------------------------
# Tool 2: BrowserClickTool
# ---------------------------------------------------------------------------


@ToolRegistry.register("browser_click")
class BrowserClickTool(BaseTool):
    """Click an element on the page."""

    tool_id = "browser_click"
    is_local = False

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name="browser_click",
            description=(
                "Dispatch one click on a uniquely resolved element. Observe the"
                " page first and pass its document_id. Ambiguous targets are"
                " refused; a click timeout is never retried automatically."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "document_id": {
                        "type": "string",
                        "description": "Document identity from the latest observation.",
                    },
                    "selector": {
                        "type": "string",
                        "description": (
                            "Visible text of the element, a CSS selector, or"
                            " a short description (e.g. 'first video result')."
                        ),
                    },
                    "by_text": {
                        "type": "boolean",
                        "description": (
                            "If true, click by text content"
                            " instead of CSS selector. Default: false."
                        ),
                    },
                    "target": {
                        "type": "string",
                        "description": "Alias for selector.",
                    },
                    "text": {
                        "type": "string",
                        "description": "Alias for selector, for visible element text.",
                    },
                    "element": {
                        "type": "string",
                        "description": "Alias for selector.",
                    },
                    "query": {
                        "type": "string",
                        "description": "Alias for selector.",
                    },
                },
                # Require one accepted spelling without forcing callers to
                # use ``selector`` when an advertised alias is supplied.
                "anyOf": [
                    {"required": ["selector"]},
                    {"required": ["target"]},
                    {"required": ["text"]},
                    {"required": ["element"]},
                    {"required": ["query"]},
                ],
                "required": ["document_id"],
            },
            category="browser",
            requires_confirmation=True,
            effect=ToolEffect.MUTATING,
        )

    _ORDINALS = {"first": 0, "second": 1, "third": 2, "fourth": 3, "last": -1}

    # Filler words stripped from natural-language descriptions before
    # keyword matching ("the first video result" -> "video"). Derive the
    # ordinal entries from the supported mapping so adding one cannot leave it
    # behind as a literal role-name keyword.
    _DESC_STOPWORDS = frozenset(
        "the a an top main big red blue green"
        " result results item element link button option entry row".split()
    ) | frozenset(_ORDINALS)

    @_browser_operation(lambda: _session)
    def execute(self, **params: Any) -> ToolResult:
        # Models routinely name this param `target`, `text`, `element` or
        # `query` instead of `selector`; rejecting those costs the whole
        # workflow, so accept the common aliases.
        selector = str(
            params.get("selector")
            or params.get("target")
            or params.get("text")
            or params.get("element")
            or params.get("query")
            or ""
        ).strip()
        if not selector:
            return ToolResult(
                tool_name="browser_click",
                content=(
                    "No selector provided. Pass the visible text of the"
                    " element or a CSS selector."
                ),
                success=False,
            )

        by_text = params.get("by_text", False)

        try:
            page = _session.page
            document_id = params.get("document_id")
            _session.require_document(document_id)
            strategy = self._resolve_and_click(
                page,
                selector,
                by_text,
                expected_document=document_id,
            )
            return ToolResult(
                tool_name="browser_click",
                content=f"Click dispatched to element: {selector}; verify the result.",
                success=True,
                metadata={
                    "selector": selector,
                    "by_text": by_text,
                    "strategy": strategy,
                    "document_id": _session.document_id,
                },
                execution_state=ExecutionState.EXECUTED,
            )
        except ImportError:
            return ToolResult(
                tool_name="browser_click",
                content=(
                    "playwright not installed. Install with: uv sync --extra browser"
                ),
                success=False,
            )
        except Exception as exc:
            return ToolResult(
                tool_name="browser_click",
                content=f"Click error: {exc}",
                success=False,
                execution_state=(
                    exc.state
                    if isinstance(exc, BrowserActionError)
                    else ExecutionState.UNKNOWN_OUTCOME
                ),
                metadata={"failure": getattr(exc, "failure", "TOOL_FAILURE")},
            )

    def _resolve_and_click(
        self,
        page: Any,
        selector: str,
        by_text: bool,
        *,
        expected_document: str | None = None,
    ) -> str:
        """Resolve across frames, require uniqueness, then dispatch once.

        Use DOM handles to pin identity. No strategy or target fallback is
        allowed after dispatch. Explicit ordinals apply across actionable
        matches only; an ambiguous non-ordinal request fails closed.
        """
        import re

        words = [w for w in re.split(r"\W+", selector.lower()) if w]
        ordinal_match = re.match(
            r"^(?:the )?(first|second|third|fourth|last)\s",
            selector.lower(),
        )
        ordinal = self._ORDINALS[ordinal_match[1]] if ordinal_match else None

        def candidates(frame: Any) -> list:
            cands = []
            if not by_text:
                cands.append(("css", frame.locator(selector)))
            cands.append(("text-exact", frame.get_by_text(selector, exact=True)))
            cands.append(
                ("text-fuzzy", frame.get_by_text(re.compile(re.escape(selector), re.I)))
            )
            # YouTube search results: "first video result" must click a
            # video title, not the "Videos" filter chip — so this outranks
            # the generic role-based keyword match below.
            try:
                url = frame.url or ""
            except Exception:
                url = ""
            if "youtube." in url and ("video" in words or "result" in words):
                cands.append(("youtube-result", frame.locator("a#video-title")))
            keywords = [w for w in words if w not in self._DESC_STOPWORDS]
            if keywords:
                pat = re.compile(".*".join(re.escape(k) for k in keywords), re.I)
                for role in ("link", "button"):
                    cands.append((f"role-{role}", frame.get_by_role(role, name=pat)))
            return cands

        # Snapshot actual DOM handles. Locators/nth can silently resolve to a
        # replacement node between observation and action; handles cannot.
        frames = list(page.frames)
        per_frame = [(index, candidates(frame)) for index, frame in enumerate(frames)]
        for strategy in (
            "css",
            "text-exact",
            "text-fuzzy",
            "youtube-result",
            "role-link",
            "role-button",
        ):
            matches = []
            for frame_index, frame_candidates in per_frame:
                for name, locator in frame_candidates:
                    if name != strategy:
                        continue
                    try:
                        handles = locator.element_handles()
                    except Exception as exc:
                        # Invalid natural-language CSS is a resolution miss.
                        # Other observation failures cannot authorize fallback.
                        if strategy == "css" and (
                            "selector" in str(exc).lower()
                            or "unexpected token" in str(exc).lower()
                        ):
                            continue
                        raise BrowserActionError("STALE_TARGET", str(exc)) from exc
                    for handle in handles:
                        try:
                            if handle.is_visible() and handle.is_enabled():
                                matches.append((frame_index, handle))
                        except Exception as exc:
                            raise BrowserActionError("STALE_TARGET", str(exc)) from exc
            if not matches:
                continue
            if ordinal is None and len(matches) != 1:
                raise BrowserActionError(
                    "AMBIGUOUS_TARGET",
                    f"{len(matches)} actionable matches for '{selector}' ({strategy})",
                )
            index = len(matches) - 1 if ordinal == -1 else ordinal or 0
            if index >= len(matches):
                raise BrowserActionError("TARGET_NOT_FOUND", "Requested ordinal absent")
            frame_index, handle = matches[index]
            if expected_document is not None:
                _session.require_document(expected_document)
                _session.require_observed_target(handle)
            try:
                handle.click(timeout=8000 if frame_index == 0 else 4000)
            except Exception as exc:
                # Dispatch might have occurred. Do not try another handle,
                # another strategy, or another frame after this point.
                raise BrowserActionError(
                    "UNKNOWN_OUTCOME",
                    str(exc),
                    dispatched=True,
                ) from exc
            return strategy
        raise BrowserActionError(
            "TARGET_NOT_FOUND",
            f"No actionable element matched '{selector}'",
        )


# ---------------------------------------------------------------------------
# Tool 3: BrowserTypeTool
# ---------------------------------------------------------------------------


@ToolRegistry.register("browser_type")
class BrowserTypeTool(BaseTool):
    """Type text into a form field."""

    tool_id = "browser_type"
    is_local = False

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name="browser_type",
            description=(
                "Type text into a form field on the current page."
                " Pass document_id from a fresh observation. Requires one"
                " field and verifies the resulting value."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "document_id": {
                        "type": "string",
                        "description": "Document identity from the latest observation.",
                    },
                    "selector": {
                        "type": "string",
                        "description": "CSS selector of the input field.",
                    },
                    "text": {
                        "type": "string",
                        "description": "Text to type into the field.",
                    },
                    "clear": {
                        "type": "boolean",
                        "description": (
                            "If true, clear the field before typing. Default: true."
                        ),
                    },
                },
                "required": ["selector", "text", "document_id"],
            },
            category="browser",
            requires_confirmation=True,
            effect=ToolEffect.MUTATING,
        )

    @_browser_operation(lambda: _session)
    def execute(self, **params: Any) -> ToolResult:
        selector = params.get("selector", "")
        text = params.get("text", "")

        if not selector:
            return ToolResult(
                tool_name="browser_type",
                content="No selector provided.",
                success=False,
            )
        if not text:
            return ToolResult(
                tool_name="browser_type",
                content="No text provided.",
                success=False,
            )

        clear = params.get("clear", True)

        try:
            page = _session.page
            document_id = params.get("document_id")
            _session.require_document(document_id)
            handles = page.locator(selector).element_handles()
            handles = [h for h in handles if h.is_visible() and h.is_enabled()]
            if len(handles) != 1:
                raise BrowserActionError(
                    "AMBIGUOUS_TARGET" if handles else "TARGET_NOT_FOUND",
                    f"Expected one input, found {len(handles)}",
                )
            handle = handles[0]
            _session.require_observed_target(handle)
            before = handle.input_value()
            expected = text if clear else before + text
            _session.require_document(document_id)
            try:
                if clear:
                    handle.fill(text, timeout=8000)
                else:
                    handle.focus()
                    handle.evaluate(
                        "el => el.setSelectionRange(el.value.length, el.value.length)"
                    )
                    handle.type(text, timeout=8000)
                observed = handle.input_value()
                _session.require_document(document_id)
            except Exception as exc:
                raise BrowserActionError(
                    "UNKNOWN_OUTCOME",
                    str(exc),
                    dispatched=True,
                ) from exc
            if observed != expected:
                raise BrowserActionError(
                    "VERIFICATION_FAILURE",
                    "Field value differs after typing",
                    dispatched=True,
                )

            return ToolResult(
                tool_name="browser_type",
                content=f"Typed text into: {selector}",
                success=True,
                metadata={
                    "selector": selector,
                    "document_id": document_id,
                    "verification": "input_value matched expected value",
                },
                execution_state=ExecutionState.VERIFIED,
            )
        except ImportError:
            return ToolResult(
                tool_name="browser_type",
                content=(
                    "playwright not installed. Install with: uv sync --extra browser"
                ),
                success=False,
            )
        except Exception as exc:
            return ToolResult(
                tool_name="browser_type",
                content=f"Type error: {exc}",
                success=False,
                execution_state=(
                    exc.state
                    if isinstance(exc, BrowserActionError)
                    else ExecutionState.UNKNOWN_OUTCOME
                ),
                metadata={"failure": getattr(exc, "failure", "TOOL_FAILURE")},
            )


# ---------------------------------------------------------------------------
# Tool 4: BrowserScreenshotTool
# ---------------------------------------------------------------------------


@ToolRegistry.register("browser_screenshot")
class BrowserScreenshotTool(BaseTool):
    """Take a screenshot of the current page."""

    tool_id = "browser_screenshot"
    is_local = False

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name="browser_screenshot",
            description=(
                "Take a screenshot of the current browser page."
                " Returns the screenshot as base64-encoded data."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Optional file path to save the screenshot.",
                    },
                    "full_page": {
                        "type": "boolean",
                        "description": (
                            "If true, capture the full scrollable page. Default: false."
                        ),
                    },
                },
            },
            category="browser",
        )

    @_browser_operation(lambda: _session)
    def execute(self, **params: Any) -> ToolResult:
        path = params.get("path")
        full_page = params.get("full_page", False)

        try:
            page = _session.page
            screenshot_bytes = page.screenshot(full_page=full_page)

            if path:
                with open(path, "wb") as f:
                    f.write(screenshot_bytes)

            b64_data = base64.b64encode(screenshot_bytes).decode("utf-8")
            targets = _session.observe_targets()

            description = "Screenshot taken"
            if full_page:
                description += " (full page)"
            if path:
                description += f", saved to {path}"

            return ToolResult(
                tool_name="browser_screenshot",
                content=description,
                success=True,
                metadata={
                    "screenshot_base64": b64_data,
                    "document_id": _session.document_id,
                    "targets": targets,
                },
            )
        except ImportError:
            return ToolResult(
                tool_name="browser_screenshot",
                content=(
                    "playwright not installed. Install with: uv sync --extra browser"
                ),
                success=False,
            )
        except Exception as exc:
            return ToolResult(
                tool_name="browser_screenshot",
                content=f"Screenshot error: {exc}",
                success=False,
            )


# ---------------------------------------------------------------------------
# Tool 5: BrowserExtractTool
# ---------------------------------------------------------------------------


@ToolRegistry.register("browser_extract")
class BrowserExtractTool(BaseTool):
    """Extract content from the current page."""

    tool_id = "browser_extract"
    is_local = False

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name="browser_extract",
            description=(
                "Extract content from the current browser page."
                " Supports extracting text, links, or tables."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "selector": {
                        "type": "string",
                        "description": (
                            "CSS selector to extract from. Default: 'body'."
                        ),
                    },
                    "extract_type": {
                        "type": "string",
                        "description": (
                            "Type of extraction: 'text', 'links',"
                            " or 'tables'. Default: 'text'."
                        ),
                    },
                },
            },
            category="browser",
            effect=ToolEffect.READ_ONLY,
        )

    @_browser_operation(lambda: _session)
    def execute(self, **params: Any) -> ToolResult:
        selector = params.get("selector", "body")
        extract_type = params.get("extract_type", "text")

        if extract_type not in ("text", "links", "tables"):
            return ToolResult(
                tool_name="browser_extract",
                content=(
                    f"Invalid extract_type: '{extract_type}'."
                    " Must be 'text', 'links', or 'tables'."
                ),
                success=False,
            )

        try:
            page = _session.page
            targets = _session.observe_targets()

            if extract_type == "text":
                content = page.inner_text(selector)
                if len(content) > 10000:
                    content = content[:10000] + "\n\n[Content truncated]"
                return ToolResult(
                    tool_name="browser_extract",
                    content=content,
                    success=True,
                    metadata={
                        "selector": selector,
                        "extract_type": extract_type,
                        "document_id": _session.document_id,
                        "targets": targets,
                    },
                )

            elif extract_type == "links":
                links = page.eval_on_selector_all(
                    f"{selector} a[href]",
                    """elements => elements.map(el => ({
                        href: el.href,
                        text: el.innerText.trim()
                    }))""",
                )
                lines = []
                for link in links:
                    text = link.get("text", "")
                    href = link.get("href", "")
                    lines.append(f"- [{text}]({href})")
                content = "\n".join(lines) if lines else "No links found."
                if len(content) > 10000:
                    content = content[:10000] + "\n\n[Content truncated]"
                return ToolResult(
                    tool_name="browser_extract",
                    content=content,
                    success=True,
                    metadata={
                        "selector": selector,
                        "extract_type": extract_type,
                        "num_links": len(links),
                        "document_id": _session.document_id,
                        "targets": targets,
                    },
                )

            else:  # tables
                tables_text = page.eval_on_selector_all(
                    f"{selector} table",
                    """elements => elements.map(el => el.innerText)""",
                )
                if tables_text:
                    content = "\n\n---\n\n".join(tables_text)
                else:
                    content = "No tables found."
                if len(content) > 10000:
                    content = content[:10000] + "\n\n[Content truncated]"
                return ToolResult(
                    tool_name="browser_extract",
                    content=content,
                    success=True,
                    metadata={
                        "selector": selector,
                        "extract_type": extract_type,
                        "num_tables": len(tables_text),
                        "document_id": _session.document_id,
                        "targets": targets,
                    },
                )

        except ImportError:
            return ToolResult(
                tool_name="browser_extract",
                content=(
                    "playwright not installed. Install with: uv sync --extra browser"
                ),
                success=False,
            )
        except Exception as exc:
            return ToolResult(
                tool_name="browser_extract",
                content=f"Extract error: {exc}",
                success=False,
            )


__all__ = [
    "BrowserNavigateTool",
    "BrowserClickTool",
    "BrowserTypeTool",
    "BrowserScreenshotTool",
    "BrowserExtractTool",
]

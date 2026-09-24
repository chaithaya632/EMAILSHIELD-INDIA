"""
EMAILSHIELD INDIA — Shared UI Theme & Components
Modern SaaS design system inspired by Vercel, Linear, and Raycast.
Dark-first, minimal, typographic, high information density.
"""
import streamlit as st
import html as _html

# ─────────────────────────── Color Palette ───────────────────────────
COLORS = {
    "bg":           "#0a0a0a",
    "surface":      "#141414",
    "surface_2":    "#1a1a1a",
    "border":       "#262626",
    "border_light": "#333333",
    "text":         "#ededed",
    "text_secondary": "#a1a1a1",
    "text_muted":   "#666666",
    "accent":       "#3b82f6",
    "accent_hover": "#2563eb",
    "green":        "#22c55e",
    "green_bg":     "#052e16",
    "amber":        "#f59e0b",
    "amber_bg":     "#451a03",
    "red":          "#ef4444",
    "red_bg":       "#450a0a",
    "blue":         "#3b82f6",
    "blue_bg":      "#172554",
    "purple":       "#a855f7",
    "purple_bg":    "#3b0764",
    # Semantic aliases
    "primary":      "#3b82f6",
    "primary_hover": "#2563eb",
    "background":   "#0a0a0a",
    "success":      "#22c55e",
    "warning":      "#f59e0b",
    "danger":       "#ef4444",
}

# ─────────────────────────── Status Mapping ───────────────────────────
STATUS_STYLES = {
    "safe":     {"color": COLORS["green"],  "bg": COLORS["green_bg"],  "label": "Safe"},
    "warning":  {"color": COLORS["amber"],  "bg": COLORS["amber_bg"],  "label": "Warning"},
    "danger":   {"color": COLORS["red"],    "bg": COLORS["red_bg"],    "label": "Danger"},
    "info":     {"color": COLORS["blue"],   "bg": COLORS["blue_bg"],   "label": "Info"},
    "neutral":  {"color": COLORS["text_muted"], "bg": COLORS["surface_2"], "label": "—"},
}

# ─────────────────────────── Global CSS ───────────────────────────
GLOBAL_CSS = """
<style>
    /* ── Base overrides ────────────────────────── */
    .stApp {
        background-color: #0a0a0a;
    }
    section[data-testid="stSidebar"] {
        background-color: #0a0a0a;
        border-right: 1px solid #262626;
    }
    section[data-testid="stSidebar"] .stRadio label {
        font-size: 0.9rem;
        padding: 6px 0;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 0;
        border-bottom: 1px solid #262626;
    }
    .stTabs [data-baseweb="tab"] {
        padding: 10px 20px;
        font-size: 0.85rem;
        color: #a1a1a1;
        border-bottom: 2px solid transparent;
    }
    .stTabs [data-baseweb="tab"][aria-selected="true"] {
        color: #ededed;
        border-bottom: 2px solid #3b82f6;
        background-color: transparent;
    }

    /* ── Card component ────────────────────────── */
    .es-card {
        background-color: #141414;
        border: 1px solid #262626;
        border-radius: 10px;
        padding: 20px;
        margin-bottom: 12px;
    }
    .es-card-header {
        font-size: 0.78rem;
        font-weight: 500;
        color: #a1a1a1;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 8px;
    }
    .es-card-value {
        font-size: 1.8rem;
        font-weight: 700;
        color: #ededed;
        line-height: 1.2;
    }
    .es-card-subtitle {
        font-size: 0.82rem;
        color: #666666;
        margin-top: 4px;
    }

    /* ── Status badge ──────────────────────────── */
    .es-badge {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        padding: 3px 10px;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
        letter-spacing: 0.02em;
    }
    .es-badge-dot {
        width: 6px;
        height: 6px;
        border-radius: 50%;
        display: inline-block;
    }

    /* ── Empty state ───────────────────────────── */
    .es-empty {
        text-align: center;
        padding: 48px 24px;
        color: #666666;
    }
    .es-empty-icon {
        font-size: 2.4rem;
        margin-bottom: 12px;
    }
    .es-empty-title {
        font-size: 1.05rem;
        font-weight: 600;
        color: #a1a1a1;
        margin-bottom: 6px;
    }
    .es-empty-body {
        font-size: 0.85rem;
        color: #666666;
        max-width: 380px;
        margin: 0 auto;
    }

    /* ── Section header ────────────────────────── */
    .es-section-title {
        font-size: 0.78rem;
        font-weight: 600;
        color: #a1a1a1;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        margin: 24px 0 12px 0;
        padding-bottom: 8px;
        border-bottom: 1px solid #1a1a1a;
    }

    /* ── Table rows ────────────────────────────── */
    .es-row {
        display: flex;
        align-items: center;
        padding: 10px 16px;
        border-bottom: 1px solid #1a1a1a;
        font-size: 0.88rem;
        color: #ededed;
    }
    .es-row:hover {
        background-color: #141414;
    }
    .es-row-label {
        flex: 1;
        color: #a1a1a1;
    }
    .es-row-value {
        font-weight: 500;
        color: #ededed;
    }

    /* ── Page header ───────────────────────────── */
    .es-page-header {
        margin-bottom: 28px;
    }
    .es-page-title {
        font-size: 1.5rem;
        font-weight: 700;
        color: #ededed;
        margin: 0 0 4px 0;
    }
    .es-page-subtitle {
        font-size: 0.88rem;
        color: #666666;
    }

    /* ── Metric mini ───────────────────────────── */
    .es-metric-mini {
        display: flex;
        align-items: baseline;
        gap: 8px;
    }
    .es-metric-mini-value {
        font-size: 1.15rem;
        font-weight: 700;
        color: #ededed;
    }
    .es-metric-mini-label {
        font-size: 0.78rem;
        color: #666666;
    }

    /* ── Hide default header anchor links ──────── */
    .stMarkdown a.header-link { display: none; }

    /* ── Responsive columns ────────────────────── */
    @media (max-width: 768px) {
        .es-card-value { font-size: 1.4rem; }
    }
</style>
"""

# ─────────────────────────── Helper Functions ───────────────────────────

def inject_theme():
    """Inject the global CSS theme. Call once at the top of each page."""
    st.markdown(GLOBAL_CSS, unsafe_allow_html=True)


def page_header(title: str, subtitle: str = ""):
    """Render a clean page header."""
    sub_html = f'<div class="es-page-subtitle">{_html.escape(subtitle)}</div>' if subtitle else ""
    st.markdown(
        f'<div class="es-page-header">'
        f'<div class="es-page-title">{_html.escape(title)}</div>'
        f'{sub_html}'
        f'</div>',
        unsafe_allow_html=True
    )


def metric_card(label: str, value, subtitle: str = "", color: str = ""):
    """Render a single metric card. Returns the st.markdown element."""
    val_style = f'color: {color};' if color else ''
    st.markdown(
        f'<div class="es-card">'
        f'<div class="es-card-header">{_html.escape(str(label))}</div>'
        f'<div class="es-card-value" style="{val_style}">{_html.escape(str(value))}</div>'
        f'<div class="es-card-subtitle">{_html.escape(str(subtitle))}</div>'
        f'</div>',
        unsafe_allow_html=True
    )


def status_badge(status: str, label: str = ""):
    """Render an inline status badge. status: safe|warning|danger|info|neutral"""
    style = STATUS_STYLES.get(status, STATUS_STYLES["neutral"])
    display_label = _html.escape(label or style["label"])
    return (
        f'<span class="es-badge" style="color:{style["color"]};background:{style["bg"]}">'
        f'<span class="es-badge-dot" style="background:{style["color"]}"></span>'
        f'{display_label}'
        f'</span>'
    )


def status_badge_html(status: str, label: str = "") -> str:
    """Return badge HTML string without rendering."""
    return status_badge(status, label)


def empty_state(icon: str = "ℹ️", title: str = "", body: str = "", message: str = ""):
    """Render a centered empty-state placeholder."""
    if not body and message:
        body = message
    if not title:
        title = icon
        icon = "ℹ️"
    body_html = f'<div class="es-empty-body">{_html.escape(body)}</div>' if body else ""
    st.markdown(
        f'<div class="es-empty">'
        f'<div class="es-empty-icon">{icon}</div>'
        f'<div class="es-empty-title">{_html.escape(title)}</div>'
        f'{body_html}'
        f'</div>',
        unsafe_allow_html=True
    )


def section_divider(title: str = ""):
    """Render a subtle section divider with optional title."""
    if not title:
        st.markdown('<hr style="border: none; border-top: 1px solid #262626; margin: 20px 0;">', unsafe_allow_html=True)
        return
    st.markdown(
        f'<div class="es-section-title">{_html.escape(title)}</div>',
        unsafe_allow_html=True
    )


def detail_row(label: str, value: str, mono: bool = False):
    """Render a label-value detail row."""
    val_html = f'<code style="color:#ededed;font-size:0.85rem">{_html.escape(str(value))}</code>' if mono else _html.escape(str(value))
    st.markdown(
        f'<div class="es-row">'
        f'<span class="es-row-label">{_html.escape(str(label))}</span>'
        f'<span class="es-row-value">{val_html}</span>'
        f'</div>',
        unsafe_allow_html=True
    )


def error_card(title: str, message: str = "", icon: str = "⚠️"):
    """Render an error card with red accent."""
    if not message:
        message = title
        title = "Error"
    st.markdown(
        f'<div class="es-card" style="border-color:{COLORS["red"]}">'
        f'<div class="es-card-header" style="color:{COLORS["red"]}">{icon} {_html.escape(title)}</div>'
        f'<div style="font-size:0.88rem;color:{COLORS["text_secondary"]}">{_html.escape(message)}</div>'
        f'</div>',
        unsafe_allow_html=True
    )


def info_card(title: str, message: str = "", icon: str = "ℹ️"):
    """Render an info card with blue accent."""
    if not message:
        message = title
        title = "Information"
    st.markdown(
        f'<div class="es-card" style="border-color:{COLORS["blue"]}">'
        f'<div class="es-card-header" style="color:{COLORS["blue"]}">{icon} {_html.escape(title)}</div>'
        f'<div style="font-size:0.88rem;color:{COLORS["text_secondary"]}">{_html.escape(message)}</div>'
        f'</div>',
        unsafe_allow_html=True
    )


def success_card(title: str, message: str = "", icon: str = "✅"):
    """Render a success card with green accent."""
    if not message:
        message = title
        title = "Success"
    st.markdown(
        f'<div class="es-card" style="border-color:{COLORS["green"]}">'
        f'<div class="es-card-header" style="color:{COLORS["green"]}">{icon} {_html.escape(title)}</div>'
        f'<div style="font-size:0.88rem;color:{COLORS["text_secondary"]}">{_html.escape(message)}</div>'
        f'</div>',
        unsafe_allow_html=True
    )


/**
 * pixa-content — Pure JS sanitizer (replaces WASM module)
 *
 * Drop-in replacement for @pixagram/sanitizer.
 * Uses sanitize-html (replaces ammonia) and marked (replaces pulldown-cmark).
 *
 * Exports (same signatures as the WASM module):
 *   default       — pixaContentInit(): Promise<void>  (no-op, kept for compat)
 *   sanitizePost  — (body, optionsJson) → { html, links, images }
 *   sanitizeComment — (body, optionsJson) → { html, links }
 *   sanitizeMemo  — (body, optionsJson) → { html }
 *   safeJson      — (jsonStr) → sanitized JSON string
 *   safeString    — (s, maxLen) → string | null
 *   extractPlainText — (body) → string
 *   summarizeContent — (body, sentenceCount) → { summary, keywords, sentences, total_sentences }
 *   sanitizeUsername — (username) → string
 *
 * @version 1.0.0
 */

import sanitizeHtmlLib from 'sanitize-html';
import { marked } from 'marked';

// ═══════════════════════════════════════════════════════════
// Marked configuration
// ═══════════════════════════════════════════════════════════

marked.setOptions({
    gfm: true,
    breaks: false,
    pedantic: false,
    headerIds: false,
    mangle: false,
});

// ═══════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════

const DEFAULT_INTERNAL_DOMAINS = [
    'pixa.pics', 'pixagram.io', 'hive.blog', 'peakd.com', 'ecency.com',
    'hivesigner.com', 'hive-keychain.com', 'splinterlands.com',
    'images.hive.blog', 'files.peakd.com', 'steemitimages.com', 'imgp.steemit.com',
];

const DEFAULT_OPTIONS = {
    internal_domains: ['pixa.pics', 'pixagram.io', 'hive.blog', 'peakd.com', 'ecency.com'],
    max_body_length: 500_000,
    max_image_count: 0,
};

const VALID_KEY_RE = /^[a-zA-Z_][a-zA-Z0-9_\-]{0,63}$/;
const BASE64_IMAGE_RE = /^data:image\/(png|jpeg|jpg|gif|webp|svg\+xml|bmp|ico|avif);base64,[A-Za-z0-9+/=]+$/;

// JSON sanitizer limits
const MAX_DEPTH = 5;
const MAX_STRING_LEN = 10_000;
const MAX_IMAGE_STRING_LEN = 7_000_000;
const MAX_ARRAY_LEN = 100;
const MAX_OBJECT_KEYS = 50;

// ═══════════════════════════════════════════════════════════
// Text Utilities
// ═══════════════════════════════════════════════════════════

function isPredominantlyHtml(content) {
    const trimmed = content.trim();
    if (trimmed.startsWith('<!') || trimmed.startsWith('<html') ||
        trimmed.startsWith('<div') || trimmed.startsWith('<p>') || trimmed.startsWith('<p ')) {
        return true;
    }

    const htmlIndicators = [
        '<p>', '<p ', '</p>', '<div', '</div>',
        '<h1', '<h2', '<h3', '<h4', '<h5', '<h6',
        '<table', '<tr', '<td', '<ul>', '<ol>', '</ul>', '</ol>',
        '<blockquote', '</blockquote>',
        '<br>', '<br/>', '<br />',
        '<hr>', '<hr/>', '<hr />',
    ];
    const mdIndicators = [
        '\n# ', '\n## ', '\n### ',
        '\n- ', '\n* ', '\n1. ',
        '\n> ', '\n```', '\n---', '\n***', '\n___', '\n|',
    ];

    let htmlCount = 0;
    for (const ind of htmlIndicators) {
        let idx = -1;
        while ((idx = content.indexOf(ind, idx + 1)) !== -1) htmlCount++;
    }
    let mdCount = 0;
    for (const ind of mdIndicators) {
        let idx = -1;
        while ((idx = content.indexOf(ind, idx + 1)) !== -1) mdCount++;
    }

    return htmlCount > mdCount && htmlCount >= 2;
}

function markdownToHtml(md) {
    return marked.parse(md);
}

const HTML_ENTITY_MAP = {
    '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"',
    '&apos;': "'", '&#x27;': "'", '&#39;': "'", '&nbsp;': ' ',
    '&ndash;': '\u2013', '&mdash;': '\u2014',
    '&lsquo;': '\u2018', '&rsquo;': '\u2019',
    '&ldquo;': '\u201c', '&rdquo;': '\u201d',
    '&hellip;': '\u2026', '&copy;': '\u00a9', '&reg;': '\u00ae',
    '&trade;': '\u2122', '&euro;': '\u20ac', '&pound;': '\u00a3',
    '&yen;': '\u00a5', '&cent;': '\u00a2', '&deg;': '\u00b0',
    '&times;': '\u00d7', '&divide;': '\u00f7', '&bull;': '\u2022',
    '&rarr;': '\u2192', '&larr;': '\u2190', '&uarr;': '\u2191', '&darr;': '\u2193',
};

function decodeHtmlEntities(text) {
    let result = text;
    for (const [entity, replacement] of Object.entries(HTML_ENTITY_MAP)) {
        result = result.replaceAll(entity, replacement);
    }
    // Numeric entities: &#123; and &#x00A9;
    result = result.replace(/&(#?[a-zA-Z0-9_]+);/g, (match, entity) => {
        if (entity.startsWith('#x') || entity.startsWith('#X')) {
            const code = parseInt(entity.slice(2), 16);
            return (isFinite(code) && code > 0) ? String.fromCodePoint(code) : match;
        } else if (entity.startsWith('#')) {
            const code = parseInt(entity.slice(1), 10);
            return (isFinite(code) && code > 0) ? String.fromCodePoint(code) : match;
        }
        return match; // Unknown named entity — leave as-is
    });
    return result;
}

function htmlToPlainText(html) {
    let text = html;
    // Replace <br> with newline
    text = text.replace(/<br[ \t\n\r]*\/?>/gi, '\n');
    // Replace block elements with newlines
    text = text.replace(/<\/?(p|div|h[1-6]|li|tr|blockquote|section|article|figure|figcaption|details|summary|dt|dd)(?:[ \t\n\r/][^>]*)?>/gi, '\n');
    // Replace <hr> with newline
    text = text.replace(/<hr[ \t\n\r]*\/?>/gi, '\n');
    // Strip remaining tags
    text = text.replace(/<[^>]+>/g, '');
    // Decode entities
    text = decodeHtmlEntities(text);
    // Clean up whitespace line by line
    text = text.split('\n').map(l => l.trim()).join('\n');
    // Collapse 3+ newlines
    text = text.replace(/\n{3,}/g, '\n\n');
    return text.trim();
}

function normalizeWhitespace(text) {
    return text.trim().replace(/[ \t\n\r\f]+/g, ' ');
}

function truncateIfNeeded(body, maxLen) {
    if (maxLen > 0 && body.length > maxLen) {
        const truncated = body.slice(0, maxLen);
        // Try to avoid splitting inside an HTML tag
        const lastLt = truncated.lastIndexOf('<');
        if (lastLt !== -1 && lastLt > maxLen - 200) {
            return truncated.slice(0, lastLt);
        }
        return truncated;
    }
    return body;
}

// ═══════════════════════════════════════════════════════════
// Image Utilities
// ═══════════════════════════════════════════════════════════

const IMG_TAG_RE = /<img[ \t\n\r][^>]*>/gi;
const SRC_ATTR_RE = /src[ \t\n\r]*=[ \t\n\r]*["']([^"']+)["']/i;
const ALT_ATTR_RE = /alt[ \t\n\r]*=[ \t\n\r]*["']([^"']*)["']/i;

function isValidBase64Image(dataUri) {
    if (dataUri.length > 7_000_000) return false;
    if (!BASE64_IMAGE_RE.test(dataUri)) return false;

    // Extra check for SVG: no script elements
    if (dataUri.startsWith('data:image/svg+xml;base64,')) {
        try {
            const b64 = dataUri.slice('data:image/svg+xml;base64,'.length);
            const decoded = atob(b64).toLowerCase();
            if (decoded.includes('<script') || decoded.includes('javascript:') ||
                decoded.includes('onerror') || decoded.includes('onload') ||
                decoded.includes('onclick') || decoded.includes('eval(')) {
                return false;
            }
        } catch { return false; }
    }
    return true;
}

function isValidImageUrl(url) {
    if (!url.startsWith('http://') && !url.startsWith('https://') && !url.startsWith('//')) return false;
    const lower = url.toLowerCase();
    if (lower.includes('javascript:') || lower.includes('data:') || lower.includes('vbscript:')) return false;
    if (url.length > 4096) return false;
    return true;
}

function extractImages(html) {
    const images = [];
    let index = 0;
    let match;
    const re = new RegExp(IMG_TAG_RE.source, 'gi');
    while ((match = re.exec(html)) !== null) {
        const tag = match[0];
        const srcMatch = SRC_ATTR_RE.exec(tag);
        if (!srcMatch) continue;
        const src = srcMatch[1];
        if (!src) continue;

        const altMatch = ALT_ATTR_RE.exec(tag);
        const alt = altMatch ? altMatch[1] : '';
        const isBase64 = src.startsWith('data:');

        if (isBase64 && !isValidBase64Image(src)) continue;
        if (!isBase64 && !isValidImageUrl(src)) continue;

        images.push({ src, alt, is_base64: isBase64, index });
        index++;
    }
    return images;
}

function limitImages(html, maxCount) {
    let count = 0;
    return html.replace(/<img[ \t\n\r][^>]*>/gi, (match) => {
        count++;
        return count <= maxCount ? match : '';
    });
}

// ═══════════════════════════════════════════════════════════
// Mentions & Hashtags
// ═══════════════════════════════════════════════════════════

const MENTION_RE = /(^|[ \t\n\r>(])@([a-zA-Z][a-zA-Z0-9.\-]{2,15})/g;
const HASHTAG_RE = /(^|[ \t\n\r>(])#([a-zA-Z][a-zA-Z0-9\-]{0,31})/g;

function htmlEscape(s) {
    return s.replace(/&/g, '&amp;').replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function isValidUsername(username) {
    const len = username.length;
    if (len < 3 || len > 16) return false;
    if (!/^[a-z]/.test(username)) return false;
    if (/[.\-]$/.test(username)) return false;
    if (!/^[a-z0-9.\-]+$/.test(username)) return false;
    if (/[.\-]{2}/.test(username)) return false;
    return true;
}

function isMentionContinuation(text, pos) {
    if (pos >= text.length) return false;
    const c = text.charCodeAt(pos);
    return (c >= 0x61 && c <= 0x7a) || (c >= 0x41 && c <= 0x5a) ||
        (c >= 0x30 && c <= 0x39) || c === 0x2e || c === 0x2d;
}

function isHashtagContinuation(text, pos) {
    if (pos >= text.length) return false;
    const c = text.charCodeAt(pos);
    return (c >= 0x61 && c <= 0x7a) || (c >= 0x41 && c <= 0x5a) ||
        (c >= 0x30 && c <= 0x39) || c === 0x2d;
}

function replaceWithBoundaryCheck(text, re, isContinuation, makeReplacement) {
    re.lastIndex = 0;
    let result = '';
    let lastEnd = 0;
    let match;

    while ((match = re.exec(text)) !== null) {
        if (match.index < lastEnd) continue;
        // Trailing boundary check
        if (isContinuation(text, match.index + match[0].length)) continue;

        const prefix = match[1];
        const ident = match[2];
        const replacement = makeReplacement(ident);
        if (replacement !== null) {
            // Emit text before prefix, then prefix, then replacement
            const prefixStart = match.index;
            const prefixLen = prefix.length;
            result += text.slice(lastEnd, prefixStart) + prefix + replacement;
            lastEnd = match.index + match[0].length;
        }
    }
    result += text.slice(lastEnd);
    return result;
}

function processMentionsAndTags(html) {
    let result = '';
    let pos = 0;
    let linkDepth = 0;

    while (pos < html.length) {
        if (html[pos] === '<') {
            const tagEnd = findTagEnd(html, pos);
            if (tagEnd !== -1) {
                const tag = html.slice(pos, tagEnd + 1);
                const lower = tag.toLowerCase();
                if (lower.startsWith('<a ') || lower === '<a>') linkDepth++;
                else if (lower.startsWith('</a>') || lower.startsWith('</a ')) linkDepth = Math.max(0, linkDepth - 1);
                result += tag;
                pos = tagEnd + 1;
            } else {
                result += '<';
                pos++;
            }
        } else {
            let textStart = pos;
            while (pos < html.length && html[pos] !== '<') pos++;
            const text = html.slice(textStart, pos);
            if (linkDepth > 0) {
                result += text;
            } else {
                let processed = replaceWithBoundaryCheck(text, new RegExp(MENTION_RE.source, 'g'), isMentionContinuation, (username) => {
                    const lower = username.toLowerCase();
                    if (!isValidUsername(lower)) return null;
                    const esc = htmlEscape(lower);
                    return `<a href="/@${esc}" class="pixa-mention" data-username="${esc}">@${esc}</a>`;
                });
                processed = replaceWithBoundaryCheck(processed, new RegExp(HASHTAG_RE.source, 'g'), isHashtagContinuation, (tag) => {
                    const lower = tag.toLowerCase();
                    const esc = htmlEscape(lower);
                    return `<a href="/trending/${esc}" class="pixa-hashtag">#${esc}</a>`;
                });
                result += processed;
            }
        }
    }
    return result;
}

function findTagEnd(html, start) {
    let pos = start + 1;
    let inQuote = false;
    let quoteChar = '';
    while (pos < html.length) {
        const c = html[pos];
        if (inQuote) {
            if (c === quoteChar) inQuote = false;
        } else if (c === '"' || c === "'") {
            inQuote = true;
            quoteChar = c;
        } else if (c === '>') {
            return pos;
        }
        pos++;
    }
    return -1;
}

// ═══════════════════════════════════════════════════════════
// Link Processing
// ═══════════════════════════════════════════════════════════

const LINK_TAG_RE = /(<a[ \t\n\r][^>]*>)([\s\S]*?)<\/a>/gi;
const HREF_ATTR_RE = /href[ \t\n\r]*=[ \t\n\r]*["']([^"']+)["']/i;

function extractDomain(href) {
    try {
        const urlStr = href.startsWith('//') ? `https:${href}` : href;
        return new URL(urlStr).hostname;
    } catch { return ''; }
}

function isInternalDomain(domain, customDomains) {
    const lower = domain.toLowerCase();
    const allDomains = [...DEFAULT_INTERNAL_DOMAINS, ...customDomains];
    return allDomains.some(d => {
        const dl = d.toLowerCase();
        return lower === dl || lower.endsWith(`.${dl}`);
    });
}

function htmlEscapeAttr(s) {
    return s.replace(/&/g, '&amp;').replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function stripHtmlTags(s) {
    let result = '';
    let inTag = false;
    for (const c of s) {
        if (c === '<') inTag = true;
        else if (c === '>') inTag = false;
        else if (!inTag) result += c;
    }
    return result;
}

function processLinks(html, customInternalDomains) {
    const links = [];
    const result = html.replace(LINK_TAG_RE, (fullMatch, openTag, innerText) => {
        const hrefMatch = HREF_ATTR_RE.exec(openTag);
        if (!hrefMatch) return fullMatch;
        const href = hrefMatch[1];
        if (!href) return fullMatch;

        // Skip mention/hashtag links
        if (openTag.includes('pixa-mention') || openTag.includes('pixa-hashtag')) {
            links.push({ href, text: stripHtmlTags(innerText), domain: '', is_external: false });
            return fullMatch;
        }

        const domain = extractDomain(href);
        const isExternal = !href.startsWith('/') && !href.startsWith('#') &&
            !href.startsWith('mailto:') && domain !== '' &&
            !isInternalDomain(domain, customInternalDomains);

        links.push({ href, text: stripHtmlTags(innerText), domain, is_external: isExternal });

        if (isExternal) {
            return `<a href="${htmlEscapeAttr(href)}" class="pixa-external-link" data-external="true" data-domain="${htmlEscapeAttr(domain)}" rel="noopener noreferrer" target="_blank">${innerText}</a>`;
        }
        return fullMatch;
    });
    return { html: result, links };
}

// ═══════════════════════════════════════════════════════════
// sanitize-html configurations (replaces ammonia tiers)
// ═══════════════════════════════════════════════════════════

const MEMO_SANITIZE_CONFIG = {
    allowedTags: ['strong', 'b', 'em', 'i', 'a'],
    allowedAttributes: {
        'a': ['href', 'class', 'data-username'],
    },
    allowedSchemes: ['https', 'mailto'],
    transformTags: {
        'a': sanitizeHtmlLib.simpleTransform('a', { rel: 'noopener noreferrer' }),
    },
};

const COMMENT_SANITIZE_CONFIG = {
    allowedTags: [
        'strong', 'b', 'em', 'i', 'a',
        'p', 'br',
        'blockquote', 'pre', 'code',
        'ul', 'ol', 'li',
        'u', 's', 'del', 'sub', 'sup', 'mark', 'small',
    ],
    allowedAttributes: {
        'a': ['href', 'title', 'rel', 'class', 'data-username'],
        'code': ['data-language'],
        '*': ['class'],
    },
    allowedSchemes: ['http', 'https', 'mailto'],
    transformTags: {
        'a': sanitizeHtmlLib.simpleTransform('a', { rel: 'noopener noreferrer' }),
    },
};

const POST_SANITIZE_CONFIG = {
    allowedTags: [
        // Block
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'p', 'br', 'hr',
        'div', 'span', 'section',
        'blockquote', 'pre', 'code',
        'table', 'thead', 'tbody', 'tfoot', 'tr', 'th', 'td',
        'caption', 'colgroup', 'col',
        'ul', 'ol', 'li',
        'dl', 'dt', 'dd',
        'figure', 'figcaption',
        'details', 'summary',
        'center',
        // Inline
        'a', 'strong', 'b', 'em', 'i', 'u',
        's', 'del', 'ins', 'mark',
        'small', 'sub', 'sup',
        'abbr', 'cite', 'q', 'kbd', 'var', 'samp', 'time',
        'ruby', 'rt', 'rp',
        // Media — images only
        'img',
    ],
    allowedAttributes: {
        'a': ['href', 'title', 'rel', 'class', 'data-username'],
        'img': ['src', 'alt', 'title', 'width', 'height', 'loading'],
        'td': ['colspan', 'rowspan', 'align'],
        'th': ['colspan', 'rowspan', 'align', 'scope'],
        'col': ['span'],
        'colgroup': ['span'],
        'code': ['data-language'],
        'pre': ['data-language'],
        'time': ['datetime'],
        'blockquote': ['cite'],
        'abbr': ['title'],
        '*': ['class'],
    },
    allowedSchemes: ['http', 'https', 'mailto'],
    allowedSchemesByTag: {
        img: ['http', 'https', 'data'],
    },
    allowProtocolRelative: true,
    transformTags: {
        'a': sanitizeHtmlLib.simpleTransform('a', { rel: 'noopener noreferrer' }),
    },
    // Preserve validated base64 data URIs on img.src
    allowedSchemesAppliedToAttributes: ['href', 'cite'],
};

const STRIP_ALL_CONFIG = {
    allowedTags: [],
    allowedAttributes: {},
};

// ═══════════════════════════════════════════════════════════
// Body Tier 1: Memo
// ═══════════════════════════════════════════════════════════

export function sanitizeMemo(body, optionsJson) {
    if (!body) return { html: '' };

    const opts = parseOptions(optionsJson);

    // Guard: data URIs in memos are never legitimate
    if (body.trim().startsWith('data:')) return { html: '' };

    // Encrypted memo (#) — base58, not HTML
    if (body.startsWith('#')) {
        const safe = sanitizeHtmlLib(body, STRIP_ALL_CONFIG);
        return { html: `<span class="pixa-encrypted-memo">${safe}</span>` };
    }

    const input = truncateIfNeeded(body, Math.min(opts.max_body_length, 2048));
    const htmlRaw = isPredominantlyHtml(input) ? input : markdownToHtml(input);
    const htmlWithMentions = processMentionsAndTags(htmlRaw);
    const html = sanitizeHtmlLib(htmlWithMentions, MEMO_SANITIZE_CONFIG);

    return { html };
}

// ═══════════════════════════════════════════════════════════
// Body Tier 2: Comment
// ═══════════════════════════════════════════════════════════

export function sanitizeComment(body, optionsJson) {
    if (!body) return { html: '', links: [] };

    const opts = parseOptions(optionsJson);

    // Guard: data URIs in comments are never legitimate
    if (body.trim().startsWith('data:')) return { html: '', links: [] };

    const input = truncateIfNeeded(body, opts.max_body_length);
    const htmlRaw = isPredominantlyHtml(input) ? input : markdownToHtml(input);
    const htmlWithMentions = processMentionsAndTags(htmlRaw);
    const htmlSanitized = sanitizeHtmlLib(htmlWithMentions, COMMENT_SANITIZE_CONFIG);
    const { html: htmlFinal, links } = processLinks(htmlSanitized, opts.internal_domains);

    return { html: htmlFinal, links };
}

// ═══════════════════════════════════════════════════════════
// Body Tier 3: Post
// ═══════════════════════════════════════════════════════════

export function sanitizePost(body, optionsJson) {
    if (!body) return { html: '', links: [], images: [] };

    const opts = parseOptions(optionsJson);

    // ── Pixel art short-circuit ──────────────────────────
    const trimmed = body.trim();
    if (trimmed.startsWith('data:image/')) {
        if (isValidBase64Image(trimmed)) {
            return {
                html: '',
                images: [{ src: trimmed, alt: '', is_base64: true, index: 0 }],
                links: [],
            };
        }
        return { html: '', links: [], images: [] };
    }

    // ── Standard pipeline ────────────────────────────────
    const input = truncateIfNeeded(body, opts.max_body_length);
    const htmlRaw = isPredominantlyHtml(input) ? input : markdownToHtml(input);

    // Extract images BEFORE sanitization
    const extractedImages = extractImages(htmlRaw);

    const htmlWithMentions = processMentionsAndTags(htmlRaw);
    const htmlSanitized = sanitizeHtmlLib(htmlWithMentions, POST_SANITIZE_CONFIG);
    const { html: htmlWithLinks, links: extractedLinks } = processLinks(htmlSanitized, opts.internal_domains);

    const htmlFinal = (opts.max_image_count > 0)
        ? limitImages(htmlWithLinks, opts.max_image_count)
        : htmlWithLinks;

    return { html: htmlFinal, links: extractedLinks, images: extractedImages };
}

// ═══════════════════════════════════════════════════════════
// JSON Primitives
// ═══════════════════════════════════════════════════════════

export function safeJson(jsonStr) {
    if (!jsonStr) return '{}';
    try {
        const raw = JSON.parse(jsonStr);
        const clean = safeValue(raw, 0);
        return clean !== null ? JSON.stringify(clean) : '{}';
    } catch {
        return '{}';
    }
}

function safeKey(key) {
    return VALID_KEY_RE.test(key);
}

export function safeString(s, maxLen) {
    if (typeof s !== 'string') return null;

    // 1. Reject embedded JSON
    if (isEmbeddedJson(s)) return null;

    const trimmed = s.trim();
    if (!trimmed) return null;

    // 2. Valid base64 image — pass through
    if (trimmed.startsWith('data:image/')) {
        if (isValidBase64Image(trimmed)) {
            return trimmed.length <= maxLen ? trimmed : null;
        }
        return null;
    }

    // 3. Reject dangerous URI schemes
    const lower = trimmed.toLowerCase();
    if (lower.startsWith('javascript:') || lower.startsWith('vbscript:') || lower.startsWith('data:')) {
        return null;
    }

    // 4. URL vs text
    const isUrl = lower.startsWith('https://') || lower.startsWith('http://') ||
        lower.startsWith('//') || lower.startsWith('mailto:') || lower.startsWith('tel:');

    let cleaned;
    if (isUrl) {
        // URLs: strip control chars only
        cleaned = trimmed.replace(/[\x00-\x1f\x7f]/g, '');
    } else {
        // Text: strip ALL HTML
        const stripped = sanitizeHtmlLib(trimmed, STRIP_ALL_CONFIG);
        // Re-check dangerous schemes after entity decoding
        const strippedLower = stripped.toLowerCase();
        if (strippedLower.includes('javascript:') || strippedLower.includes('vbscript:')) {
            return null;
        }
        // Strip control chars (keep newlines and tabs)
        cleaned = stripped.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '');
    }

    const result = cleaned.trim();
    if (!result) return null;

    // 5. Length limit
    if (result.length > maxLen) {
        return result.slice(0, maxLen).trimEnd() || null;
    }
    return result;
}

function isEmbeddedJson(s) {
    const t = s.trim();
    if (t.length < 2) return false;
    if (t[0] !== '{' && t[0] !== '[') return false;
    try { JSON.parse(t); return true; } catch { return false; }
}

function safeValue(value, depth) {
    if (depth > MAX_DEPTH) return null;

    if (value === null) return null;
    if (value === undefined) return null;

    const type = typeof value;

    if (type === 'string') {
        const limit = value.trim().startsWith('data:image/') ? MAX_IMAGE_STRING_LEN : MAX_STRING_LEN;
        return safeString(value, limit);
    }

    if (type === 'number') {
        return isFinite(value) ? value : null;
    }

    if (type === 'boolean') return value;

    if (Array.isArray(value)) {
        return value.slice(0, MAX_ARRAY_LEN)
            .map(v => safeValue(v, depth + 1))
            .filter(v => v !== null);
    }

    if (type === 'object') {
        const clean = {};
        const keys = Object.keys(value).slice(0, MAX_OBJECT_KEYS);
        for (const k of keys) {
            if (!safeKey(k)) continue;
            const cleanV = safeValue(value[k], depth + 1);
            if (cleanV !== null) clean[k] = cleanV;
        }
        return clean;
    }

    return null;
}

// ═══════════════════════════════════════════════════════════
// Username Sanitization
// ═══════════════════════════════════════════════════════════

export function sanitizeUsername(username) {
    if (!username) return '';
    const trimmed = username.trim().toLowerCase();
    if (trimmed.length < 3 || trimmed.length > 16) return '';
    if (!/^[a-z]/.test(trimmed)) return '';
    if (!/^[a-z0-9.\-]+$/.test(trimmed)) return '';
    if (/[.\-]{2}/.test(trimmed)) return '';
    if (/[.\-]$/.test(trimmed)) return '';
    return trimmed;
}

// ═══════════════════════════════════════════════════════════
// Plain Text Extraction
// ═══════════════════════════════════════════════════════════

export function extractPlainText(body) {
    if (!body) return '';
    if (body.trim().startsWith('data:')) return '';

    const html = isPredominantlyHtml(body) ? body : markdownToHtml(body);
    const plain = htmlToPlainText(html);
    return normalizeWhitespace(plain);
}

// ═══════════════════════════════════════════════════════════
// TF-IDF Summarization
// ═══════════════════════════════════════════════════════════

const STOP_WORDS = new Set([
    'a', 'an', 'the', 'is', 'it', 'of', 'in', 'to', 'and', 'or', 'for',
    'on', 'at', 'by', 'be', 'as', 'so', 'if', 'do', 'no', 'up', 'he',
    'we', 'my', 'me', 'am', 'are', 'was', 'has', 'had', 'not', 'but',
    'its', 'his', 'her', 'she', 'him', 'our', 'you', 'all', 'can', 'did',
    'get', 'got', 'may', 'who', 'how', 'now', 'out', 'own', 'too', 'than',
    'that', 'them', 'then', 'they', 'this', 'from', 'with', 'what', 'when',
    'will', 'been', 'have', 'just', 'more', 'also', 'into', 'some', 'such',
    'very', 'your', 'much', 'were', 'here', 'there', 'which', 'about',
    'their', 'would', 'could', 'should', 'these', 'those', 'being', 'other',
    'after', 'where', 'while', 'because', 'through', 'between', 'before', 'during',
    'https', 'http', 'www', 'com', 'org', 'html',
]);

function tokenize(text) {
    return text.toLowerCase()
        .split(/[^a-zA-Z0-9']+/)
        .map(w => w.replace(/^'+|'+$/g, ''))
        .filter(w => w.length > 1 && !STOP_WORDS.has(w));
}

function splitSentences(text) {
    if (!text.trim()) return [];
    const sentences = [];
    const re = /[.!?]+(?:[ \t\n\r]+|$)/g;
    let remaining = text.trim();
    let match;

    while ((match = re.exec(remaining)) !== null) {
        const sentence = remaining.slice(0, match.index + match[0].length).trim();
        if (sentence.length > 2) sentences.push(sentence);
        remaining = remaining.slice(match.index + match[0].length);
        re.lastIndex = 0;
    }
    remaining = remaining.trim();
    if (remaining.length > 2) sentences.push(remaining);
    return sentences;
}

function summarize(plainText, sentenceCount) {
    const sentences = splitSentences(plainText);

    if (!sentences.length) {
        return { summary: '', sentences: [], total_sentences: 0, keywords: [] };
    }

    const count = Math.min(sentenceCount, sentences.length);
    const totalSentences = sentences.length;
    const allTokens = tokenize(plainText);
    const totalWords = allTokens.length;

    if (totalWords === 0) {
        return {
            summary: sentences[0] || '',
            sentences: sentences.slice(0, count).map((text, i) => ({ text, score: 0, position: i })),
            total_sentences: totalSentences,
            keywords: [],
        };
    }

    // Word frequencies
    const wordFreq = {};
    for (const token of allTokens) {
        wordFreq[token] = (wordFreq[token] || 0) + 1;
    }

    // TF scores
    const tfScores = {};
    for (const [word, freq] of Object.entries(wordFreq)) {
        tfScores[word] = freq / totalWords;
    }

    // Score sentences
    let scored = sentences.map((sentence, pos) => {
        const tokens = tokenize(sentence);
        const tokenCount = tokens.length;
        if (tokenCount === 0) return { text: sentence, score: 0, position: pos };

        const score = tokens.reduce((sum, t) => sum + (tfScores[t] || 0), 0) / tokenCount;
        const positionBonus = totalSentences > 1 ? 0.2 * (1 - pos / totalSentences) : 0;
        const lengthPenalty = tokenCount < 5 ? 0.5 : 1.0;
        const punctuationBonus = /[.!?]$/.test(sentence) ? 1.0 : 0.85;

        return {
            text: sentence,
            score: score * lengthPenalty * punctuationBonus + positionBonus,
            position: pos,
        };
    });

    // Top N by score
    scored.sort((a, b) => b.score - a.score);
    let top = scored.slice(0, count);
    // Re-sort by original position
    top.sort((a, b) => a.position - b.position);

    const summary = top.map(s => s.text).join(' ');

    // Top keywords
    let keywords = Object.entries(wordFreq)
        .map(([word, freq]) => ({ word, score: freq / totalWords }))
        .sort((a, b) => b.score - a.score)
        .slice(0, 10);

    return { summary, sentences: top, total_sentences: totalSentences, keywords };
}

export function summarizeContent(body, sentenceCount) {
    if (!body) return { summary: '', keywords: [], sentences: [], total_sentences: 0 };
    const plain = extractPlainText(body);
    const count = sentenceCount === 0 ? 3 : sentenceCount;
    return summarize(plain, count);
}

// ═══════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════

function parseOptions(optionsJson) {
    if (!optionsJson) return { ...DEFAULT_OPTIONS };
    try {
        const parsed = typeof optionsJson === 'string' ? JSON.parse(optionsJson) : optionsJson;
        return { ...DEFAULT_OPTIONS, ...parsed };
    } catch {
        return { ...DEFAULT_OPTIONS };
    }
}

// ═══════════════════════════════════════════════════════════
// Init (no-op, WASM compat)
// ═══════════════════════════════════════════════════════════

export default async function pixaContentInit() {
    // No-op — pure JS, nothing to initialize.
    // Kept for API compatibility with the WASM module.
}
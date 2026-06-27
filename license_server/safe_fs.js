'use strict';

const fs   = require('fs');
const path = require('path');

/**
 * Returns true when `child` resides inside `parent` (or is the same directory).
 * Symlinks are NOT dereferenced — use fs.realpathSync first if that matters.
 */
function isInside(child, parent) {
    const rel = path.relative(parent, child);
    return rel === '' || (!!rel && !rel.startsWith('..') && !path.isAbsolute(rel));
}

/**
 * Join `base` with `segments`, normalize the result, and verify it stays
 * inside the resolved `base`.  Throws on path-traversal attempts.
 *
 *   const file = safeResolve(DATA_DIR, 'sub', 'licenses.json');
 *   fs.readFileSync(file, 'utf8');   // safe — already validated
 */
function safeResolve(base, ...segments) {
    const resolvedBase = path.resolve(String(base || ''));
    const joined       = path.join(resolvedBase, ...segments);
    const normalized   = path.normalize(joined);
    if (!isInside(normalized, resolvedBase)) {
        throw new Error(`Path traversal blocked: "${joined}" is outside base "${resolvedBase}".`);
    }
    return normalized;
}

/**
 * Validate that `filePath` is inside `baseDir` after normalization.
 * Returns the normalized path on success; throws on violation.
 * Useful when the caller already has a full path (e.g. from an env var).
 */
function verifyInside(filePath, baseDir) {
    const normalized = path.normalize(String(filePath || ''));
    const resolvedBase = path.resolve(String(baseDir || ''));
    if (!normalized.startsWith(resolvedBase + path.sep) && normalized !== resolvedBase) {
        throw new Error(`Path traversal blocked: "${filePath}" is outside "${resolvedBase}".`);
    }
    return normalized;
}

module.exports = { isInside, safeResolve, verifyInside };

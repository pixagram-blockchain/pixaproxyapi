/**
 * Pixa Blockchain Proxy API System with LacertaDB
 * Complete API wrapper with organized method groups
 * @version 3.6.1
 *
 * API Groups and Methods:
 *
 * PixaProxyAPI (Main Class):
 *   - initialize(config)
 *   - restoreSession()
 *   - logout()
 *   - initializeVault(pin, options)
 *   - isVaultInitialized()
 *   - unlockWithPin(pin, options)
 *   - isPinEnabled()
 *   - requiresUnlock(keyType)
 *   - validateCredentials(account, key, keyType)
 *   - quickLogin(account, key, keyType, options)
 *   - disconnect()
 *   - updateConfig(newConfig)
 *   - formatAccount(account)
 *   - processPost(post, renderOptions)
 *   - processComment(comment, renderOptions)
 *   - processMemo(memo)
 *   - extractPlainText(body)
 *   - summarizeContent(body, sentenceCount)
 *   - sanitizeUsername(rawUsername)
 *   - hasVaultConfig()
 *
 * database (DatabaseAPI):
 *   - call(method, params)
 *   - getDatabaseInfo()
 *
 * tags (TagsAPI):
 *   - getTrendingTags(afterTag, limit)
 *   - getDiscussionsByTrending(query)
 *   - getDiscussionsByCreated(query)
 *   - getDiscussionsByHot(query)
 *   - getDiscussionsByPromoted(query)
 *   - getDiscussionsByPayout(query)
 *   - getDiscussionsByVotes(query)
 *   - getDiscussionsByActive(query)
 *   - getDiscussionsByChildren(query)
 *   - getDiscussionsByMuted(query)
 *
 * blocks (BlocksAPI):
 *   - getBlock(blockNum)
 *   - getBlockHeader(blockNum)
 *   - getOpsInBlock(blockNum, onlyVirtual)
 *
 * globals (GlobalsAPI):
 *   - getDynamicGlobalProperties()
 *   - getChainProperties()
 *   - getFeedHistory()
 *   - getCurrentMedianHistoryPrice()
 *   - getHardforkVersion()
 *   - getRewardFund(name)
 *   - getVestingDelegations(account, from, limit)
 *   - getConfig()
 *   - getVersion()
 *
 * accounts (AccountsAPI):
 *   - getAccounts(accounts, forceRefresh)
 *   - lookupAccounts(lowerBound, limit)
 *   - lookupAccountNames(accounts)
 *   - getAccountCount()
 *   - getAccountHistory(account, from, limit, operationBitmask)
 *   - getAccountReputations(lowerBound, limit)
 *   - getAccountNotifications(account, limit)
 *
 * market (MarketAPI):
 *   - getOrderBook(limit)
 *   - getOpenOrders(account)
 *   - getTicker()
 *   - getTradeHistory(start, end, limit)
 *   - getMarketHistory(bucketSeconds, start, end)
 *   - getMarketHistoryBuckets()
 *
 * authority (AuthorityAPI):
 *   - getOwnerHistory(account)
 *   - getRecoveryRequest(account)
 *   - getWithdrawRoutes(account, type)
 *   - getAccountBandwidth(account, type)
 *   - getSavingsWithdrawFrom(account)
 *   - getSavingsWithdrawTo(account)
 *   - verifyAuthority(stx)
 *
 * votes (VotesAPI):
 *   - getActiveVotes(author, permlink)
 *   - getAccountVotes(account)
 *
 * content (ContentAPI):
 *   - getContent(author, permlink)
 *   - getContentReplies(author, permlink)
 *   - getDiscussionsByAuthorBeforeDate(author, startPermlink, beforeDate, limit)
 *   - getRepliesByLastUpdate(author, startPermlink, limit)
 *   - getDiscussionsByComments(query)
 *   - getDiscussionsByBlog(query)
 *   - getDiscussionsByFeed(query)
 *   - getAccountPosts(account, sort, limit, options)
 *   - getState(path)
 *
 * witnesses (WitnessesAPI):
 *   - getWitnessByAccount(account)
 *   - getWitnessesByVote(from, limit)
 *   - lookupWitnessAccounts(lowerBound, limit)
 *   - getWitnessCount()
 *   - getActiveWitnesses()
 *   - getWitnessSchedule()
 *
 * follow (FollowAPI):
 *   - getFollowers(account, startFollower, type, limit)
 *   - getFollowing(account, startFollowing, type, limit)
 *   - getFollowCount(account)
 *   - getFeedEntries(account, startEntryId, limit)
 *   - getBlogEntries(account, startEntryId, limit)
 *   - getRebloggedBy(author, permlink)
 *   - getBlogAuthors(account)
 *   - getSubscriptions(account)
 *
 * broadcast (BroadcastAPI):
 *   - updateAccount2(params)
 *   - updateProfile(account, profileObject)
 *   - vote(voter, author, permlink, weight)
 *   - comment(params)
 *   - commentOptions(params)
 *   - transfer(from, to, amount, memo)
 *   - transferToVesting(from, to, amount)
 *   - withdrawVesting(account, vestingShares)
 *   - delegateVestingShares(delegator, delegatee, vestingShares)
 *   - transferToSavings(from, to, amount, memo)
 *   - transferFromSavings(from, requestId, to, amount, memo)
 *   - cancelTransferFromSavings(from, requestId)
 *   - claimRewardBalance(account, rewardPixa, rewardPxs, rewardVests)
 *   - recurrentTransfer(params)
 *   - follow(follower, following)
 *   - unfollow(follower, following)
 *   - mute(follower, following)
 *   - reblog(account, author, permlink)
 *   - customJson(params)
 *   - deleteComment(author, permlink)
 *   - accountCreate(params)
 *   - accountCreateWithDelegation(params)
 *   - accountWitnessVote(account, witness, approve)
 *   - accountWitnessProxy(account, proxy)
 *   - witnessUpdate(params)
 *   - setWithdrawVestingRoute(fromAccount, toAccount, percent, autoVest)
 *   - limitOrderCreate(params)
 *   - limitOrderCancel(owner, orderId)
 *   - convertPixa(owner, amount, requestId)
 *   - sendOperations(operations, key)
 *
 * auth (AuthAPI):
 *   - isWif(key)
 *   - toWif(username, password, role)
 *   - wifToPublic(wif)
 *   - signMessage(message, wif)
 *   - verifySignature(message, signature, publicKey)
 *
 * formatter (FormatterAPI):
 *   - reputation(rawReputation)
 *   - vestToPixa(vestingShares, totalVestingShares, totalVestingFundPixa)
 *   - pixaToVest(pixa, totalVestingShares, totalVestingFundPixa)
 *   - vestToSteem() [deprecated alias]
 *   - steemToVest() [deprecated alias]
 *   - formatAsset(amount, symbol, precision)
 *
 * blockchain (BlockchainAPI):
 *   - getBlockHeader(blockNum)
 *   - getBlock(blockNum)
 *   - getTransaction(txId)
 *   - getTransactionHex(tx)
 *   - getCurrentBlockNum(mode)
 *   - getCurrentBlockHeader(mode)
 *   - getCurrentBlock(mode)
 *   - getBlockNumbers(options) [AsyncGenerator]
 *   - getBlocks(options) [AsyncGenerator]
 *   - getOperations(options) [AsyncGenerator]
 *   - getBlockNumberStream()
 *   - getBlockStream()
 *   - getOperationsStream()
 *
 * rc (ResourceCreditsAPI):
 *   - getResourceParams()
 *   - getResourcePool()
 *   - findRcAccounts(accounts)
 *   - getRCMana(account)
 *   - getVPMana(account)
 *   - calculateRCCost(operationType, operationData)
 *
 * communities (CommunitiesAPI):
 *   - getCommunity(name, observer)
 *   - listCommunities(options)
 *   - getSubscriptions(account)
 *   - getRankedPosts(options)
 *   - getAccountPosts(account, sort, options)
 *
 * keys (AccountByKeyAPI):
 *   - getKeyReferences(keys)
 *
 * transaction (TransactionStatusAPI):
 *   - findTransaction(transactionId, expiration)
 */

import { LacertaDB } from '@pixagram/lacerta-db';
import pixaContentInit, {
    sanitizePost as wasmSanitizePost,
    sanitizeComment as wasmSanitizeComment,
    sanitizeMemo as wasmSanitizeMemo,
    safeJson as wasmSafeJson,
    safeString as wasmSafeString,
    extractPlainText as wasmExtractPlainText,
    summarizeContent as wasmSummarizeContent,
    sanitizeUsername as wasmSanitizeUsername,
} from '@pixagram/sanitizer';
import {
    Client,
    PrivateKey,
    PublicKey,
    Signature,
    cryptoUtils,
    Asset,
    Price,
    Memo,
    utils,
    Types,
    BlockchainMode,
    getVestingSharePrice,
    getVests,
    VERSION,
    DEFAULT_CHAIN_ID,
    NETWORK_ID
} from '@pixagram/dpixa';
import EventEmitter from 'events';

// ============================================
// Configuration
// ============================================

const CONFIG = {
    PBKDF2_ITERATIONS: 1000 * 1000,
    CACHE_TTL: {
        posts: 60 * 1000,
        accounts: 24 * 60 * 60 * 1000,
        comments: 60 * 1000,
        trending: 5 * 60 * 1000,
        feed: 30 * 1000,
        communities: 60 * 60 * 1000,
        rewards: 5 * 60 * 1000,
        search: 10 * 60 * 1000,
        blocks: 30 * 1000,
        witnesses: 5 * 60 * 1000,
        market: 60 * 1000,
        global_props: 10 * 1000
    },
    ENTITY_TTL: {
        accounts: 24 * 60 * 60 * 1000,
        posts: 5 * 60 * 1000,
        comments: 2 * 60 * 1000,
    },
    QUERY_TTL: {
        trending: 5 * 60 * 1000,
        created: 30 * 1000,
        hot: 3 * 60 * 1000,
        promoted: 5 * 60 * 1000,
        active: 60 * 1000,
        blog: 60 * 1000,
        feed: 30 * 1000,
        comments: 60 * 1000,
        votes: 60 * 1000,
        children: 60 * 1000,
        cashout: 60 * 1000,
        content: 60 * 1000,
        content_replies: 60 * 1000,
        account_lookup: 10 * 60 * 1000,
        notifications: 30 * 1000,
    },
    SESSION_TIMEOUT: 30 * 60 * 1000,
    PIN_TIMEOUT: 5 * 60 * 1000,
    MIN_PIN_LENGTH: 6,
    PIN_MAX_ATTEMPTS: 10,
    PIN_LOCKOUT_MS: 5 * 60 * 1000,
    DEFAULT_NODES: [
        'https://cors-header-proxy-with-api.omnibus-39a.workers.dev'
    ],
    APP_NAME: 'pixagram/3.5.2',
    PAGINATION_LIMIT: 20,
    CHAIN_ID: null,
    ADDRESS_PREFIX: 'PIX',

    // Asset symbol mapping: [blockchain_symbol, display_symbol]
    // Entry[0] = on-chain name (used in broadcast operations)
    // Entry[1] = display name  (used after sanitization / in the app)
    ASSET_LIQUID: ['TESTS', 'PXA'],
    ASSET_SUPRA:  ['TBD',   'PXS'],
    ASSET_POWER:  ['VESTS', 'PXP'],
};

// ============================================
// Asset Symbol Translation
// ============================================

// Build lookup maps from CONFIG asset definitions
// fromChain: blockchain_symbol → display_symbol  (used when sanitizing data FROM the chain)
// toChain:   display_symbol → blockchain_symbol   (used when preparing data FOR broadcast)
const ASSET_MAP_FROM_CHAIN = {};
const ASSET_MAP_TO_CHAIN = {};
const ASSET_PRECISION = {};

for (const def of [CONFIG.ASSET_LIQUID, CONFIG.ASSET_SUPRA, CONFIG.ASSET_POWER]) {
    const [chainSymbol, displaySymbol] = def;
    ASSET_MAP_FROM_CHAIN[chainSymbol] = displaySymbol;
    ASSET_MAP_TO_CHAIN[displaySymbol] = chainSymbol;
}

// Precision: VESTS / PXP use 6 decimal places; all others use 3
ASSET_PRECISION[CONFIG.ASSET_POWER[0]] = 6;   // VESTS
ASSET_PRECISION[CONFIG.ASSET_POWER[1]] = 6;   // PXP
ASSET_PRECISION[CONFIG.ASSET_LIQUID[0]] = 3;   // TESTS
ASSET_PRECISION[CONFIG.ASSET_LIQUID[1]] = 3;   // PXA
ASSET_PRECISION[CONFIG.ASSET_SUPRA[0]] = 3;    // TBD
ASSET_PRECISION[CONFIG.ASSET_SUPRA[1]] = 3;    // PXS

/**
 * Parse an asset string into its numeric amount and symbol.
 * @param {string} assetStr - e.g. "123.456 TESTS" or "0.000000 VESTS"
 * @returns {{ amount: number, symbol: string, raw: string } | null}
 */
function parseAsset(assetStr) {
    if (typeof assetStr !== 'string') return null;
    const parts = assetStr.trim().split(' ');
    if (parts.length !== 2) return null;
    const amount = parseFloat(parts[0]);
    if (isNaN(amount)) return null;
    return { amount, symbol: parts[1], raw: assetStr };
}

/**
 * Format a parsed asset back to a string with the correct precision.
 * @param {number} amount
 * @param {string} symbol
 * @returns {string}
 */
function formatAssetString(amount, symbol) {
    const precision = ASSET_PRECISION[symbol] ?? 3;
    return `${amount.toFixed(precision)} ${symbol}`;
}

/**
 * Translate an asset string from blockchain symbols to display symbols.
 * Used when sanitizing data coming FROM the chain (e.g. TESTS → PXA).
 * If the symbol is not in the translation map, returns the asset as-is
 * (re-formatted with correct precision).
 *
 * @param {string} assetStr - e.g. "100.000 TESTS"
 * @returns {string} e.g. "100.000 PXA"
 */
function translateAssetFromChain(assetStr) {
    const parsed = parseAsset(assetStr);
    if (!parsed) return assetStr;
    const displaySymbol = ASSET_MAP_FROM_CHAIN[parsed.symbol] ?? parsed.symbol;
    return formatAssetString(parsed.amount, displaySymbol);
}

/**
 * Translate an asset string from display symbols to blockchain symbols.
 * Used when preparing data FOR broadcast operations (e.g. PXA → TESTS).
 * If the symbol is not in the translation map, returns the asset as-is
 * (re-formatted with correct precision).
 *
 * @param {string} assetStr - e.g. "100.000 PXA"
 * @returns {string} e.g. "100.000 TESTS"
 */
function translateAssetToChain(assetStr) {
    const parsed = parseAsset(assetStr);
    if (!parsed) return assetStr;
    const chainSymbol = ASSET_MAP_TO_CHAIN[parsed.symbol] ?? parsed.symbol;
    return formatAssetString(parsed.amount, chainSymbol);
}

// ============================================
// VALIDATORS (v3.5.0) — JS-side format checks
// ============================================

const VALIDATORS = {
    safe_asset: (s) => {
        if (typeof s !== 'string') return null;
        return /^\d{1,15}\.\d{3,6} [A-Z]{3,6}$/.test(s) ? s : null;
    },
    safe_permlink: (s) => {
        if (typeof s !== 'string') return null;
        const t = s.trim().toLowerCase();
        return /^[a-z0-9][a-z0-9\-]{0,255}$/.test(t) ? t : null;
    },
    safe_url_path: (s) => {
        if (typeof s !== 'string') return null;
        const t = s.trim();
        return /^\/@[a-z0-9][a-z0-9.\-]{1,15}\/[a-z0-9][a-z0-9\-]{0,255}(#.*)?$/.test(t) ? t : null;
    },
    safe_pubkey: (s) => {
        if (typeof s !== 'string') return null;
        return /^PIX[1-9A-HJ-NP-Za-km-z]{46,53}$/.test(s) ? s : null;
    },
    /**
     * Convert an ISO-8601 date string to a millisecond timestamp (integer).
     * Returns 0 for invalid/missing dates so `new Date(ts)` always works.
     * Blockchain dates are UTC with no trailing "Z" — we append it.
     */
    safe_timestamp: (s) => {
        if (typeof s === 'number' && Number.isFinite(s)) return s;
        if (typeof s !== 'string') return 0;
        if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(s)) return 0;
        const ms = Date.parse(s.endsWith('Z') ? s : s + 'Z');
        return Number.isFinite(ms) ? ms : 0;
    },
    safe_number: (v) => {
        return (typeof v === 'number' && Number.isFinite(v)) ? v : null;
    },
    safe_bool: (v) => {
        return (typeof v === 'boolean') ? v : null;
    },
    safe_numeric_string: (s) => {
        if (typeof s !== 'string') return null;
        return /^-?\d{1,30}$/.test(s) ? s : null;
    },
    safe_percent: (v) => {
        if (typeof v !== 'number') return null;
        return (Number.isInteger(v) && v >= 0 && v <= 10000) ? v : null;
    },
    safe_beneficiary: (b) => {
        if (!b || typeof b !== 'object') return null;
        const account = VALIDATORS.safe_username_js(b.account);
        const weight = VALIDATORS.safe_percent(b.weight);
        if (!account || weight === null) return null;
        return { account, weight };
    },
    safe_username_js: (s) => {
        if (typeof s !== 'string') return null;
        const t = s.trim().toLowerCase();
        if (t.length < 3 || t.length > 16) return null;
        if (!/^[a-z][a-z0-9.\-]{2,15}$/.test(t)) return null;
        if (/[.\-]{2}/.test(t)) return null;
        if (/[.\-]$/.test(t)) return null;
        return t;
    },
    safe_manabar: (m) => {
        if (!m || typeof m !== 'object') return null;
        return {
            current_mana: String(m.current_mana || '0'),
            last_update_time: VALIDATORS.safe_number(m.last_update_time) ?? 0,
        };
    },
    /**
     * Validate an Authority object { weight_threshold, account_auths, key_auths }.
     * These are structured chain data — NOT user-supplied text.
     */
    safe_authority: (auth) => {
        if (!auth || typeof auth !== 'object') return null;
        return {
            weight_threshold: VALIDATORS.safe_number(auth.weight_threshold) ?? 1,
            account_auths: Array.isArray(auth.account_auths)
                ? auth.account_auths.filter(a => Array.isArray(a) && a.length === 2 && typeof a[0] === 'string')
                : [],
            key_auths: Array.isArray(auth.key_auths)
                ? auth.key_auths.filter(a => Array.isArray(a) && a.length === 2 && typeof a[0] === 'string')
                : [],
        };
    },
    /**
     * Validate a single active_vote entry.
     * { voter, weight, rshares, time } — voter is a username, rest are numbers/strings.
     */
    safe_active_vote: (v, sanitizeUsername) => {
        if (!v || typeof v !== 'object') return null;
        const voter = sanitizeUsername ? sanitizeUsername(v.voter) : VALIDATORS.safe_username_js(v.voter);
        if (!voter) return null;
        return {
            voter,
            weight:  VALIDATORS.safe_number(v.weight) ?? 0,
            rshares: VALIDATORS.safe_numeric_string(String(v.rshares || '0')) || '0',
            time:    VALIDATORS.safe_timestamp(v.time),
        };
    },
};

// ============================================
// Custom Error Classes
// ============================================

class PixaAPIError extends Error {
    constructor(message, code, data = null) {
        super(message);
        this.name = 'PixaAPIError';
        this.code = code;
        this.data = data;
    }
}

class KeyNotFoundError extends PixaAPIError {
    constructor(account, keyType) {
        super(`Key not found for ${account}/${keyType}`, 'KEY_NOT_FOUND', { account, keyType });
        this.name = 'KeyNotFoundError';
    }
}

class VaultNotInitializedError extends PixaAPIError {
    constructor() {
        super('Vault not initialized. Call initializeVault() first.', 'VAULT_NOT_INITIALIZED');
        this.name = 'VaultNotInitializedError';
    }
}

class SessionExpiredError extends PixaAPIError {
    constructor(account) {
        super(`Session expired for ${account}`, 'SESSION_EXPIRED', { account });
        this.name = 'SessionExpiredError';
    }
}

class SessionNotFoundError extends PixaAPIError {
    constructor() {
        super('No active session found', 'SESSION_NOT_FOUND');
        this.name = 'SessionNotFoundError';
    }
}

// ============================================
// Utility Functions
// ============================================

const yieldToEventLoop = () => new Promise(resolve => setTimeout(resolve, 0));

/**
 * Generate random bytes (browser-compatible)
 * @param {number} length - Number of bytes
 * @returns {Uint8Array}
 */
function getRandomBytes(length) {
    if (typeof window !== 'undefined' && window.crypto) {
        return window.crypto.getRandomValues(new Uint8Array(length));
    } else if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
        return crypto.getRandomValues(new Uint8Array(length));
    } else {
        // Fallback for Node.js
        const nodeCrypto = require('crypto');
        return nodeCrypto.randomBytes(length);
    }
}

/**
 * Convert Uint8Array to hex string
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * PBKDF2 key derivation (browser-compatible)
 * @param {string} password
 * @param {string} salt - Hex string
 * @param {number} iterations
 * @param {number} keyLength - In bits
 * @returns {Promise<ArrayBuffer>}
 */
async function pbkdf2Derive(password, salt, iterations, keyLength) {
    if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
        const enc = new TextEncoder();
        const keyMaterial = await window.crypto.subtle.importKey(
            'raw',
            enc.encode(password),
            'PBKDF2',
            false,
            ['deriveBits']
        );

        const saltBuffer = new Uint8Array(salt.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

        return window.crypto.subtle.deriveBits(
            {
                name: 'PBKDF2',
                salt: saltBuffer,
                iterations: iterations,
                hash: 'SHA-512'
            },
            keyMaterial,
            keyLength
        );
    } else {
        // Fallback for Node.js
        const nodeCrypto = require('crypto');
        return new Promise((resolve, reject) => {
            nodeCrypto.pbkdf2(password, Buffer.from(salt, 'hex'), iterations, keyLength / 8, 'sha512', (err, key) => {
                if (err) reject(err);
                else resolve(key.buffer);
            });
        });
    }
}

/**
 * Normalize account name
 * @param {string|object} account
 * @returns {string|null}
 */
function normalizeAccount(account) {
    if (!account) return null;
    if (typeof account === 'string') return account.replace(/^@/, '').toLowerCase().trim() || null;
    const raw = account?.account || account?.name || '';
    return raw.replace(/^@/, '').toLowerCase().trim() || null;
}

// ============================================
// Main Pixa Proxy API Class
// ============================================

export class PixaProxyAPI {
    constructor() {
        this.lacerta = new LacertaDB();
        this.cacheDb = null;
        this.vaultDb = null;
        this.settingsDb = null;

        /** @type {Client} Single unified client for all API calls */
        this.client = null;

        this.eventEmitter = new EventEmitter();
        this.initialized = false;
        this.vaultInitialized = false;

        // Organized API groups
        this.database = null;
        this.tags = null;
        this.blocks = null;
        this.globals = null;
        this.accounts = null;
        this.market = null;
        this.authority = null;
        this.votes = null;
        this.content = null;
        this.witnesses = null;
        this.follow = null;
        this.broadcast = null;
        this.auth = null;
        this.formatter = null;
        this.blockchain = null;
        this.rc = null;
        this.communities = null;
        this.keys = null;
        this.transaction = null;

        // Internal managers
        this.keyManager = null;
        this.cacheManager = null;
        this.sessionManager = null;
        this.contentSanitizer = new ContentSanitizer();
        this.paginationManager = new PaginationManager();

        // Entity-based storage (v3.4.0)
        /** @type {SanitizationPipeline} */
        this.sanitizationPipeline = null;
        /** @type {EntityStoreManager} */
        this.entityStore = null;
        /** @type {QueryCacheManager} */
        this.queryCache = null;

        this.config = { ...CONFIG };
        this.pendingValidations = new Map();
    }

    updateConfig(newConfig) {
        this.config = { ...this.config, ...newConfig };
        if (newConfig.ENTITY_TTL) {
            this.config.ENTITY_TTL = { ...this.config.ENTITY_TTL, ...newConfig.ENTITY_TTL };
        }
        if (newConfig.QUERY_TTL) {
            this.config.QUERY_TTL = { ...this.config.QUERY_TTL, ...newConfig.QUERY_TTL };
        }
        if (this.keyManager && newConfig.PIN_TIMEOUT !== undefined) {
            this.keyManager.setPinTimeout(newConfig.PIN_TIMEOUT);
        }
        if (this.sessionManager && newConfig.SESSION_TIMEOUT !== undefined) {
            this.sessionManager.setSessionTimeout(newConfig.SESSION_TIMEOUT);
        }
        if (this.contentSanitizer && newConfig.internalDomains) {
            this.contentSanitizer.setInternalDomains(newConfig.internalDomains);
        }
    }

    async initialize(config = {}) {
        try {
            if (config.sessionTimeout) this.config.SESSION_TIMEOUT = config.sessionTimeout;
            if (config.pinTimeout) this.config.PIN_TIMEOUT = config.pinTimeout;
            if (config.enablePerformanceMonitoring) this.lacerta.performanceMonitor.startMonitoring();

            this.cacheDb = await this.lacerta.getDatabase('pixa_cache');
            this.settingsDb = await this.lacerta.getDatabase('user_settings');

            await this.setupCollections();

            const nodes = config.nodes || this.config.DEFAULT_NODES;
            const clientOptions = {};

            if (config.chainId || this.config.CHAIN_ID) {
                clientOptions.chainId = config.chainId || this.config.CHAIN_ID;
            }
            if (config.addressPrefix || this.config.ADDRESS_PREFIX) {
                clientOptions.addressPrefix = config.addressPrefix || this.config.ADDRESS_PREFIX;
            }
            if (config.timeout) {
                clientOptions.timeout = config.timeout;
            }
            if (config.failoverThreshold) {
                clientOptions.failoverThreshold = config.failoverThreshold;
            }

            // Initialize single unified client
            this.client = new Client(
                Array.isArray(nodes) ? nodes : [nodes],
                clientOptions
            );

            // Initialize all API groups
            this.database = new DatabaseAPI(this);
            this.tags = new TagsAPI(this);
            this.blocks = new BlocksAPI(this);
            this.globals = new GlobalsAPI(this);
            this.accounts = new AccountsAPI(this);
            this.market = new MarketAPI(this);
            this.authority = new AuthorityAPI(this);
            this.votes = new VotesAPI(this);
            this.content = new ContentAPI(this);
            this.witnesses = new WitnessesAPI(this);
            this.follow = new FollowAPI(this);
            this.broadcast = new BroadcastAPI(this);
            this.auth = new AuthAPI(this);
            this.formatter = new FormatterAPI(this);
            this.blockchain = new BlockchainAPI(this);
            this.rc = new ResourceCreditsAPI(this);
            this.communities = new CommunitiesAPI(this);
            this.keys = new AccountByKeyAPI(this);
            this.transaction = new TransactionStatusAPI(this);

            this.keyManager = new KeyManager(this.eventEmitter, this.config);
            this.keyManager._unlockWithPin = this.unlockWithPin.bind(this);
            await this.keyManager.setDependencies(this.settingsDb);
            this.cacheManager = new CacheManager(this.cacheDb);
            this.sessionManager = new SessionManager(this.settingsDb, this.config);
            await this.sessionManager.initialize(this.eventEmitter);

            // Initialize pixa-content WASM sanitizer
            try {
                await this.contentSanitizer.initialize(config.wasmPath || undefined);
                if (config.internalDomains) {
                    this.contentSanitizer.setInternalDomains(config.internalDomains);
                }
            } catch (wasmError) {
                // SECURITY FIX (v3.5.2): WASM sanitizer is mandatory for safe
                // content rendering. Without it, content cannot be served safely.
                if (config.allowDegradedSanitizer) {
                    console.warn('[PixaProxyAPI] pixa-content WASM init failed — DEGRADED MODE:', wasmError.message);
                } else {
                    throw new PixaAPIError(
                        'Content sanitizer (WASM) failed to initialize. Cannot serve content safely.',
                        'SANITIZER_INIT_FAILED',
                        { message: wasmError.message }
                    );
                }
            }

            /** @type {boolean} Whether the WASM sanitizer is operational */
            this.sanitizerReady = this.contentSanitizer.ready;

            // SECURITY PATCH (v3.5.2-patched): Only create entity pipeline when
            // WASM sanitizer is operational. If WASM failed and allowDegradedSanitizer
            // was set, pipeline stays null — API fallback paths will refuse to serve
            // raw data (fail-closed).
            if (this.sanitizerReady) {
                this.sanitizationPipeline = new SanitizationPipeline(this.contentSanitizer, this.formatter);
                this.entityStore = new EntityStoreManager(this.cacheDb, this.sanitizationPipeline, this.config.ENTITY_TTL);
                this.queryCache = new QueryCacheManager(this.cacheDb, this.config.QUERY_TTL);
            } else {
                this.sanitizationPipeline = null;
                this.entityStore = null;
                this.queryCache = null;
                console.warn('[PixaProxyAPI] Entity pipeline DISABLED — WASM sanitizer not ready');
            }

            this.initialized = true;
            console.log('[PixaProxyAPI] Initialized successfully v3.5.2-patched');
            return this;
        } catch (error) {
            console.error('[PixaProxyAPI] Initialization failed:', error);
            throw new PixaAPIError('Initialization failed', 'INIT_FAILED', { message: error.message });
        }
    }

    /**
     * Restore a previous session
     * @returns {Promise<string|null>} Account name if session restored, null otherwise
     */
    async restoreSession() {
        if (!this.initialized) throw new PixaAPIError('API not initialized', 'NOT_INITIALIZED');

        const activeAccount = await this.sessionManager.getActiveAccount();
        if (!activeAccount) return null;

        const sessionData = await this.sessionManager.getCurrentSession();
        const pinEnabled = sessionData?.pinEnabled || false;

        // Try to load unencrypted keys first
        const hasUnencryptedKeys = await this.keyManager.loadUnencryptedKeys(activeAccount);

        if (hasUnencryptedKeys) {
            this.keyManager.setActiveAccount(activeAccount);
            this.eventEmitter.emit('session_restored', { account: activeAccount, pinEnabled, keysLoaded: true });
            return activeAccount;
        }

        // Check if vault is available
        const hasVault = await this.hasVaultConfig();

        if (hasVault) {
            // Session exists but needs PIN to unlock keys
            this.keyManager.setActiveAccount(activeAccount);
            this.eventEmitter.emit('session_restored', {
                account: activeAccount,
                pinEnabled,
                keysLoaded: false,
                needsPIN: true
            });
            return activeAccount;
        }

        // No keys available and no vault - session is invalid
        console.warn('[restoreSession] Session exists but no keys or vault available');
        return activeAccount;
    }

    async hasVaultConfig() {
        try {
            const saltCollection = await this.settingsDb.getCollection('vault_config');
            const saltDoc = await saltCollection.get('vault_salt');
            return !!saltDoc;
        } catch (e) {
            return false;
        }
    }

    async logout() {
        const account = this.sessionManager?.getCurrentAccountSync?.() ||
            await this.sessionManager?.getActiveAccount?.();

        if (this.sessionManager) await this.sessionManager.endSession();
        if (this.keyManager) await this.keyManager.clearAllSessions(true);

        this.eventEmitter.emit('session_ended', { account });
    }

    async initializeVault(pin, options = {}) {
        if (pin.length < this.config.MIN_PIN_LENGTH) {
            throw new PixaAPIError(`PIN must be at least ${this.config.MIN_PIN_LENGTH} characters`, 'PIN_TOO_SHORT');
        }
        if (options.pinTimeout) this.config.PIN_TIMEOUT = options.pinTimeout;

        try {
            const iterations = this.config.PBKDF2_ITERATIONS;

            try { await this.settingsDb.createCollection('vault_config'); } catch (e) {}
            const saltCollection = await this.settingsDb.getCollection('vault_config');

            let existingSalt = null;
            try {
                const saltDoc = await saltCollection.get('vault_salt');
                if (saltDoc && saltDoc.salt) existingSalt = saltDoc.salt;
            } catch (e) {}

            if (!existingSalt) {
                const saltBytes = getRandomBytes(64);
                existingSalt = bytesToHex(saltBytes);
                try {
                    await saltCollection.add({ salt: existingSalt, created_at: Date.now() }, { id: 'vault_salt' });
                } catch (e) {
                    await saltCollection.update('vault_salt', { salt: existingSalt, created_at: Date.now() });
                }
            }

            // FIX: When doing a fresh vault creation (not fastMode/unlock),
            // clear any stale vault database and encryption metadata from
            // a previous session. Without this, _initializeEncryption finds
            // old wrapped-key metadata in localStorage and tries to decrypt
            // it with the new PIN, which fails with "Invalid PIN or corrupted key data".
            if (!options.fastMode && !this.vaultInitialized) {
                try {
                    await this.lacerta.dropDatabase('pixa_vault');
                } catch (dropErr) {
                    // Ignore - database may not exist yet
                }
            }

            this.vaultDb = await this.lacerta.getSecureDatabase(
                'pixa_vault', pin, existingSalt,
                {
                    iterations: iterations,
                    hashAlgorithm: 'SHA-512',
                    keyLength: 256,
                    saltLength: 64,
                    onProgress: options.onProgress || null
                }
            );

            await this.setupVaultCollections();
            await this.keyManager.setVault(this.vaultDb);

            // Store PIN verification token (HMAC of known plaintext)
            // Used by unlockWithPin to detect wrong PINs without reading vault data
            try {
                const verifyHash = await this._derivePinVerifyHash(pin, existingSalt);
                try {
                    await saltCollection.add({ hash: verifyHash, created_at: Date.now() }, { id: 'pin_verify' });
                } catch (e) {
                    await saltCollection.update('pin_verify', { hash: verifyHash, updated_at: Date.now() });
                }
            } catch (e) {
                console.warn('[initializeVault] Could not store PIN verify token:', e);
            }

            this.keyManager.setPinTimeout(this.config.PIN_TIMEOUT);
            await this.keyManager._generateSessionCryptoKey();
            this.keyManager.resetPinTimer();
            this.vaultInitialized = true;

            // Migrate any existing in-memory or unencrypted keys into the vault.
            // This covers the case where the user did quickLogin first (keys in
            // unencrypted store / sessionKeys) and then set up a vault later.
            // SKIP in fastMode — fastMode is used by unlockWithPin to open an
            // existing vault; migration there is handled separately to avoid
            // double-writes and TurboSerial deserialization errors in LacertaDB's
            // encrypted vault update path.
            if (!options.fastMode) {
                const activeAccount = this.keyManager.activeAccount ||
                    (this.sessionManager && await this.sessionManager.getActiveAccount());
                if (activeAccount) {
                    try {
                        await this.keyManager.migrateKeysToVault(activeAccount);
                    } catch (migrationErr) {
                        console.warn('[initializeVault] Key migration warning:', migrationErr.message);
                    }
                }
            }

            this.eventEmitter.emit('vault_initialized', { timestamp: Date.now() });
            return true;
        } catch (e) {
            throw new PixaAPIError('Failed to initialize vault: ' + e.message, 'VAULT_INIT_FAILED');
        }
    }

    isVaultInitialized() { return this.vaultInitialized; }

    /**
     * Derive a verification hash from PIN + salt using PBKDF2.
     * This is a SEPARATE derivation from the vault encryption key
     * (different purpose string) so it doesn't leak the vault key.
     * @param {string} pin
     * @param {string} salt - hex-encoded salt
     * @returns {Promise<string>} base64-encoded verification hash
     */
    /**
     * Derive a verification hash from PIN + salt using PBKDF2.
     * SECURITY FIX (v3.5.2): Uses explicit binary domain separation (0x02 suffix)
     * and SHA-512 (matching vault derivation algorithm) instead of string concat
     * with SHA-256. The 0x02 purpose byte ensures this derivation can never collide
     * with the vault encryption key (which uses the raw salt, implicitly purpose 0x01).
     */
    async _derivePinVerifyHash(pin, salt) {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw', encoder.encode(pin),
            { name: 'PBKDF2' }, false, ['deriveBits']
        );
        // Binary domain separation: append purpose byte 0x02 to the salt bytes
        const saltBytes = new Uint8Array(salt.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
        const purposeSalt = new Uint8Array(saltBytes.length + 1);
        purposeSalt.set(saltBytes);
        purposeSalt[saltBytes.length] = 0x02; // Purpose: pin_verify

        const bits = await crypto.subtle.deriveBits(
            {
                name: 'PBKDF2',
                salt: purposeSalt,
                iterations: this.config.PBKDF2_ITERATIONS,
                hash: 'SHA-512'
            },
            keyMaterial,
            256
        );
        return btoa(String.fromCharCode(...new Uint8Array(bits)));
    }

    async unlockWithPin(pin, options = {}) {
        const { keyType = 'posting', account } = options;

        let targetAccount = account;
        if (!targetAccount && this.sessionManager) {
            targetAccount = await this.sessionManager.getActiveAccount();
        }

        if (!targetAccount) {
            return { success: false, error: 'No active account', code: 'NO_ACCOUNT' };
        }

        const normalizedAccount = normalizeAccount(targetAccount);

        if (!pin || pin.length < this.config.MIN_PIN_LENGTH) {
            return { success: false, error: 'PIN too short', code: 'PIN_TOO_SHORT' };
        }

        try {
            // SECURITY FIX (v3.5.2): PIN attempt rate limiting
            if (this.keyManager._pinLockoutUntil > Date.now()) {
                const remainingSec = Math.ceil((this.keyManager._pinLockoutUntil - Date.now()) / 1000);
                return { success: false, error: `Too many attempts. Try again in ${remainingSec}s`, code: 'PIN_LOCKED_OUT' };
            }

            if (!this.vaultInitialized) {
                const hasVault = await this.hasVaultConfig();
                if (!hasVault) {
                    return { success: false, error: 'No vault configured', code: 'VAULT_NOT_CONFIGURED' };
                }

                try {
                    await this.initializeVault(pin, { fastMode: true });
                } catch (e) {
                    return { success: false, error: 'Invalid PIN', code: 'INVALID_PIN' };
                }
            } else {
                // Vault already initialized — verify the PIN before accepting it
                try {
                    const saltCollection = await this.settingsDb.getCollection('vault_config');
                    const saltDoc = await saltCollection.get('vault_salt');

                    if (!saltDoc || !saltDoc.salt) {
                        return { success: false, error: 'Vault configuration missing', code: 'VAULT_CONFIG_MISSING' };
                    }

                    // Try stored verification hash first (fast path)
                    let pinValid = false;
                    try {
                        const verifyDoc = await saltCollection.get('pin_verify');
                        if (verifyDoc && verifyDoc.hash) {
                            const enteredHash = await this._derivePinVerifyHash(pin, saltDoc.salt);
                            if (enteredHash !== verifyDoc.hash) {
                                return { success: false, error: 'Invalid PIN', code: 'INVALID_PIN' };
                            }
                            pinValid = true;
                        }
                    } catch (e) {
                        // pin_verify doc doesn't exist (old vault) — fall through to vault-read verification
                    }

                    if (!pinValid) {
                        // Old vault without verify token: open vault with entered PIN and try to read
                        // If wrong PIN → encrypted data won't decrypt → reads will fail or return null
                        try {
                            const testVault = await this.lacerta.getSecureDatabase(
                                'pixa_vault', pin, saltDoc.salt,
                                { iterations: this.config.PBKDF2_ITERATIONS, hashAlgorithm: 'SHA-512', keyLength: 256, saltLength: 64 }
                            );
                            // Try to actually read data — wrong key won't decrypt
                            const testCollection = await testVault.getCollection('master_keys');
                            const testRead = await testCollection.get(normalizedAccount);
                            // testRead MUST be non-null with actual keys — if null, the PIN
                            // decrypted to garbage or the wrong encryption context was used.
                            // Lacerta may not throw on wrong PIN; it just returns empty/null.
                            if (!testRead || !testRead.derived_keys) {
                                // No master keys found — also try individual keys before rejecting.
                                // User might have logged in with individual key, not master.
                                try {
                                    const testIndCollection = await testVault.getCollection('individual_keys');
                                    const testIndRead = await testIndCollection.get(`${normalizedAccount}_posting`);
                                    if (!testIndRead || !testIndRead.key) {
                                        // Neither master nor individual keys found → wrong PIN
                                        return { success: false, error: 'Invalid PIN', code: 'INVALID_PIN' };
                                    }
                                } catch (indErr) {
                                    return { success: false, error: 'Invalid PIN', code: 'INVALID_PIN' };
                                }
                            }
                            pinValid = true;

                            // Do NOT backfill pin_verify from the fallback path — the PIN
                            // was only weakly verified. pin_verify will be stored on the
                            // next full initializeVault call.
                        } catch (e) {
                            return { success: false, error: 'Invalid PIN', code: 'INVALID_PIN' };
                        }
                    }

                    // PIN verified — ALWAYS refresh vault handles to ensure they're
                    // using the correct encryption context. Stale handles from the
                    // original login may have been garbage-collected or may point to
                    // a different encryption context after tab sleep/wake.
                    try {
                        await this.keyManager.setVault(this.vaultDb);
                    } catch (e) {
                        // vaultDb handle may be stale; re-open with verified PIN
                        try {
                            this.vaultDb = await this.lacerta.getSecureDatabase(
                                'pixa_vault', pin, saltDoc.salt,
                                { iterations: this.config.PBKDF2_ITERATIONS, hashAlgorithm: 'SHA-512', keyLength: 256, saltLength: 64 }
                            );
                            await this.setupVaultCollections();
                            await this.keyManager.setVault(this.vaultDb);
                        } catch (e2) {
                            return { success: false, error: 'Vault access failed', code: 'VAULT_STALE' };
                        }
                    }
                } catch (e) {
                    return { success: false, error: 'Invalid PIN', code: 'INVALID_PIN' };
                }
            }

            // Ensure session crypto key exists for in-memory encryption
            if (!this.keyManager._sessionCryptoKey) {
                await this.keyManager._generateSessionCryptoKey();
            }
            this.keyManager.resetPinTimer();

            // Update session last activity
            await this.sessionManager.updateSession({ last_pin_unlock: Date.now() });

            // Load keys from vault into session cache
            let keysLoaded = false;
            if (this.keyManager.vaultMaster) {
                try {
                    const master = await this.keyManager.vaultMaster.get(normalizedAccount);
                    if (master && master.derived_keys) {
                        await this.keyManager.cacheKeys(normalizedAccount, master.derived_keys);
                        keysLoaded = true;
                    }
                } catch (e) {
                    console.warn('[unlockWithPin] Failed to read master keys from vault:', e.message);
                }
            }

            if (!keysLoaded && this.keyManager.vaultIndividual && keyType) {
                try {
                    const indKey = await this.keyManager.vaultIndividual.get(`${normalizedAccount}_${keyType}`);
                    if (indKey && indKey.key) {
                        await this.keyManager.addIndividualKey(normalizedAccount, keyType, indKey.key, { storeInVault: false });
                        keysLoaded = true;
                    }
                } catch (e) {
                    console.warn('[unlockWithPin] Failed to read individual key from vault:', e.message);
                }
            }

            // Fallback: try the unencrypted collection (keys from quickLogin or
            // previous sessions that weren't migrated to the vault yet).
            // Load into in-memory cache only — do NOT attempt vault migration here.
            // LacertaDB's encrypted vault update/add can fail with TurboSerial
            // deserialization errors when the vault was opened via fastMode.
            // Keys will be migrated properly on the next full initializeVault call.
            if (!keysLoaded && this.keyManager.unencrypted) {
                try {
                    const hasUnencrypted = await this.keyManager.loadUnencryptedKeys(normalizedAccount);
                    if (hasUnencrypted) {
                        console.debug('[unlockWithPin] Keys loaded from fallback store');
                        keysLoaded = true;
                    }
                } catch (e) {
                    console.warn('[unlockWithPin] Failed to load unencrypted keys:', e.message);
                }
            }

            if (!keysLoaded) {
                // PIN was correct but keys could not be loaded — don't claim success
                this.keyManager.pinVerified = false;
                this.keyManager.pinVerificationTime = 0;
                return { success: false, error: 'Keys not found in vault', code: 'KEYS_NOT_FOUND' };
            }

            // SECURITY FIX (v3.5.2): Reset attempt counter on success
            this.keyManager._pinAttempts = 0;
            this.keyManager._pinLockoutUntil = 0;
            this.eventEmitter.emit('pin_unlocked', { account: normalizedAccount });
            return { success: true, account: normalizedAccount };
        } catch (error) {
            console.error('[unlockWithPin] Error:', error);
            return { success: false, error: error.message || 'Unlock failed', code: 'UNLOCK_FAILED' };
        }
    }

    async isPinEnabled() {
        if (!this.sessionManager) return false;
        try {
            const session = await this.sessionManager.getCurrentSession();
            return session?.pinEnabled === true;
        } catch (e) {
            return false;
        }
    }

    async requiresUnlock(keyType = 'posting') {
        const account = await this.sessionManager?.getActiveAccount();
        if (!account) {
            return { needsUnlock: true, unlockType: 'login', account: null };
        }

        const normalizedAccount = normalizeAccount(account);

        if (this.keyManager.hasKey(normalizedAccount, keyType)) {
            return { needsUnlock: false, unlockType: null, account: normalizedAccount };
        }

        const session = await this.sessionManager.getCurrentSession();
        const pinEnabled = session?.pinEnabled === true;

        if (pinEnabled) {
            if (this.keyManager.isPINValid()) {
                try {
                    const key = await this.keyManager.requestKey(normalizedAccount, keyType);
                    if (key) {
                        return { needsUnlock: false, unlockType: null, account: normalizedAccount };
                    }
                } catch (e) {}
            }
            return { needsUnlock: true, unlockType: 'pin', account: normalizedAccount };
        }

        return { needsUnlock: true, unlockType: 'key', account: normalizedAccount };
    }

    async validateCredentials(account, key, keyType = 'master') {
        const normalizedAccount = normalizeAccount(account);

        if (!normalizedAccount) {
            return { valid: false, error: 'Invalid account parameter' };
        }

        // SECURITY FIX (v3.5.2): Hash the key for deduplication instead of
        // storing the first 10 characters (which leaks 9 chars of WIF entropy).
        const keyHash = bytesToHex(new Uint8Array(
            cryptoUtils.sha256(key + normalizedAccount + keyType)
        ).slice(0, 8));
        const validationKey = `${normalizedAccount}_${keyType}_${keyHash}`;
        if (this.pendingValidations.has(validationKey)) return this.pendingValidations.get(validationKey);

        const validationPromise = this._doValidation(normalizedAccount, key, keyType)
            .finally(() => this.pendingValidations.delete(validationKey));

        this.pendingValidations.set(validationKey, validationPromise);
        return validationPromise;
    }

    async _doValidation(account, key, keyType) {
        const normalizedAccount = normalizeAccount(account);

        if (!normalizedAccount) {
            return { valid: false, error: 'Invalid account parameter' };
        }

        try {
            const accounts = await this.client.database.getAccounts([normalizedAccount]);
            if (!accounts || accounts.length === 0 || !accounts[0]) {
                return { valid: false, error: 'Account not found' };
            }

            const accountData = accounts[0];

            if (keyType === 'master') {
                const postingKey = PrivateKey.fromLogin(normalizedAccount, key, 'posting');
                const publicKey = postingKey.createPublic().toString();
                // SECURITY FIX (v3.5.2): Check ALL key_auths, not just first (multi-sig support)
                const matches = accountData.posting?.key_auths?.some(([pubkey]) => pubkey === publicKey);

                if (!matches) {
                    return { valid: false, error: 'Master password does not match account keys' };
                }
                // SECURITY FIX (v3.5.2): Never return master password in result
                return { valid: true, publicKey, keyType: 'master', account: normalizedAccount };
            } else {
                let privateKey;
                try { privateKey = PrivateKey.fromString(key); } catch (e) {
                    return { valid: false, error: 'Invalid key format (not WIF)' };
                }

                const publicKey = privateKey.createPublic().toString();

                // SECURITY FIX (v3.5.2): Check all key_auths for multi-authority support
                let matches = false;
                switch (keyType) {
                    case 'posting':
                        matches = accountData.posting?.key_auths?.some(([pk]) => pk === publicKey) || false;
                        break;
                    case 'active':
                        matches = accountData.active?.key_auths?.some(([pk]) => pk === publicKey) || false;
                        break;
                    case 'owner':
                        matches = accountData.owner?.key_auths?.some(([pk]) => pk === publicKey) || false;
                        break;
                    case 'memo':
                        matches = publicKey === accountData.memo_key;
                        break;
                    default:
                        return { valid: false, error: 'Invalid key type' };
                }

                if (!matches) {
                    return { valid: false, error: `Key does not match account's ${keyType} key` };
                }
                return { valid: true, publicKey, account: normalizedAccount };
            }
        } catch (error) {
            return { valid: false, error: error.message };
        }
    }

    async quickLogin(account, key, keyType = 'master', options = {}) {
        const normalizedAccount = normalizeAccount(account);

        if (!normalizedAccount) {
            throw new PixaAPIError('Invalid account parameter', 'INVALID_ACCOUNT');
        }

        // SECURITY FIX (v3.5.2): Always validate credentials against on-chain
        // authorities. skipValidation removed — all login paths must verify keys.
        let validation = options.validation;

        if (!validation) {
            validation = await this.validateCredentials(normalizedAccount, key, keyType);
            if (!validation.valid) throw new PixaAPIError(validation.error, 'VALIDATION_FAILED');
        }

        // SECURITY FIX (v3.5.2): Always ensure session CryptoKey exists so keys
        // are encrypted in memory even for quickLogin (defense-in-depth).
        if (!this.keyManager._sessionCryptoKey) {
            await this.keyManager._generateSessionCryptoKey();
        }

        if (keyType === 'master') {
            await this.keyManager.addAccountWithMasterKey(normalizedAccount, key, { storeInVault: false });
        } else {
            await this.keyManager.addIndividualKey(normalizedAccount, keyType, key, { storeInVault: false });
        }

        // If vault is already initialized, also persist keys to the encrypted vault.
        // This ensures that PIN unlock can recover them after in-memory cache expiry.
        if (this.vaultInitialized && this.keyManager.vaultMaster) {
            try {
                await this.keyManager.migrateKeysToVault(normalizedAccount);
                console.debug('[quickLogin] Keys persisted to vault');
            } catch (e) {
                console.warn('[quickLogin] Could not persist keys to vault:', e.message);
            }
        }

        let sessionId = null;
        const shouldCreateSession = options.skipSession !== true;

        if (shouldCreateSession && this.sessionManager) {
            try {
                sessionId = await this.sessionManager.createSession(normalizedAccount, {
                    userAgent: options.userAgent || 'unknown',
                    loginType: keyType,
                    pinEnabled: false,
                    quickLogin: true
                });
            } catch (e) {
                console.warn('[quickLogin] Session creation error:', e);
                this.eventEmitter.emit('session_created', { account: normalizedAccount });
            }
        } else if (options.skipSession === true) {
            this.eventEmitter.emit('session_created', { account: normalizedAccount });
        }

        this.keyManager.setActiveAccount(normalizedAccount);
        return { success: true, account: normalizedAccount, sessionId, keyType, validation };
    }

    /**
     * Login with PIN-protected keys (for returning users)
     * @param {string} account
     * @param {string} pin
     * @param {object} options
     */
    async loginWithPin(account, pin, options = {}) {
        const normalizedAccount = normalizeAccount(account);

        if (!normalizedAccount) {
            throw new PixaAPIError('Invalid account parameter', 'INVALID_ACCOUNT');
        }

        // Check if account has stored keys in vault
        const hasVault = await this.hasVaultConfig();
        if (!hasVault) {
            throw new PixaAPIError('No vault configured. Use quickLogin first.', 'NO_VAULT');
        }

        // Initialize/unlock vault with PIN
        const unlockResult = await this.unlockWithPin(pin, { account: normalizedAccount });
        if (!unlockResult.success) {
            throw new PixaAPIError(unlockResult.error, unlockResult.code || 'UNLOCK_FAILED');
        }

        // Create session
        let sessionId = null;
        if (options.skipSession !== true && this.sessionManager) {
            sessionId = await this.sessionManager.createSession(normalizedAccount, {
                userAgent: options.userAgent || 'unknown',
                loginType: 'pin',
                pinEnabled: true
            });
        }

        this.keyManager.setActiveAccount(normalizedAccount);
        return { success: true, account: normalizedAccount, sessionId };
    }

    disconnect() {
        if (this.client && typeof this.client.disconnect === 'function') this.client.disconnect();
    }

    async setupCollections() {
        const cacheCollections = [
            'posts', 'accounts', 'comments',
            'feed_cache', 'tags', 'blocks', 'market',
            'witnesses', 'globals', 'relationships', 'rewards',
            'accounts_store', 'posts_store', 'comments_store',
            'query_cache'
        ];
        const settingsCollections = ['sessions', 'preferences', 'accounts_registry'];
        await this._setupCollectionGroup(this.cacheDb, cacheCollections, 'cache');
        await this._setupCollectionGroup(this.settingsDb, settingsCollections, 'settings');

        // v3.5.0: Create indexes on entity store collections
        await this._setupEntityIndexes();
    }

    /**
     * Index definitions per entity store collection.
     * Each index enables efficient queries without full-collection scans.
     */
    static get ENTITY_INDEXES() {
        return {
            accounts_store: [
                { field: 'id',          name: 'idx_account_id'         },
                { field: 'reputation',  name: 'idx_account_reputation' },
                { field: 'created',     name: 'idx_account_created'    },
                { field: 'last_post',   name: 'idx_account_last_post'  },
                { field: 'post_count',  name: 'idx_account_post_count' },
                { field: '_stored_at',  name: 'idx_account_stored_at'  },
            ],
            posts_store: [
                { field: 'author',               name: 'idx_post_author'         },
                { field: 'category',             name: 'idx_post_category'       },
                { field: 'created',              name: 'idx_post_created'        },
                { field: 'pending_payout_value', name: 'idx_post_pending_payout' },
                { field: 'net_votes',            name: 'idx_post_net_votes'      },
                { field: 'cashout_time',         name: 'idx_post_cashout'        },
                { field: 'depth',                name: 'idx_post_depth'          },
                { field: '_stored_at',           name: 'idx_post_stored_at'      },
            ],
            comments_store: [
                { field: 'author',          name: 'idx_comment_author'          },
                { field: 'parent_author',   name: 'idx_comment_parent_author'   },
                { field: 'parent_permlink', name: 'idx_comment_parent_permlink' },
                { field: 'created',         name: 'idx_comment_created'         },
                { field: 'net_votes',       name: 'idx_comment_net_votes'       },
                { field: 'root_author',     name: 'idx_comment_root_author'     },
                { field: 'depth',           name: 'idx_comment_depth'           },
                { field: '_stored_at',      name: 'idx_comment_stored_at'       },
            ],
            query_cache: [
                { field: 'entity_type', name: 'idx_qc_entity_type' },
                { field: 'timestamp',   name: 'idx_qc_timestamp'   },
            ],
        };
    }

    /** @private */
    async _setupEntityIndexes() {
        const indexDefs = PixaProxyAPI.ENTITY_INDEXES;
        for (const [collectionName, indexes] of Object.entries(indexDefs)) {
            try {
                const col = await this.cacheDb.getCollection(collectionName);
                for (const idx of indexes) {
                    try {
                        await col.createIndex(idx.field, { name: idx.name, unique: false });
                    } catch (e) {
                        // Index already exists or createIndex not supported — skip
                    }
                }
            } catch (e) {
                console.warn(`[PixaProxyAPI] Index setup for ${collectionName} skipped:`, e.message);
            }
        }
    }

    async _setupCollectionGroup(db, collectionNames, groupName) {
        for (const name of collectionNames) {
            try { await db.createCollection(name); }
            catch (createError) { try { await db.getCollection(name); } catch (e) {} }
        }
    }

    async setupVaultCollections() {
        const vaultCollections = ['master_keys', 'individual_keys', 'sessions'];
        return this._setupCollectionGroup(this.vaultDb, vaultCollections, 'vault');
    }

    formatAccount(account) {
        if (!account) return null;

        // SECURITY PATCH (v3.5.2-patched): Require sanitizer — fail-closed
        if (!this.sanitizerReady) {
            throw new PixaAPIError('Cannot format account: content sanitizer not ready', 'SANITIZER_NOT_READY');
        }

        // v3.5.2: Re-validate _sanitized flag
        if (account._sanitized && account._entity_type === 'account' && account._stored_at &&
            (Date.now() - account._stored_at) < (this.config.ENTITY_TTL?.accounts || 300000)) {
            return account;
        }

        // Otherwise run through sanitization pipeline if available
        if (this.sanitizationPipeline) {
            return this.sanitizationPipeline.sanitizeAccount(account);
        }

        // Legacy fallback — build field-by-field, NO spread of raw data.
        // Dangerous fields keep their names but store sanitized JSON strings.
        const safePostingMetaStr = this.contentSanitizer.safeJson(account.posting_json_metadata || '{}');
        const safeJsonMetaStr    = this.contentSanitizer.safeJson(account.json_metadata || '{}');
        let parsedPostingMeta = {};
        let parsedJsonMeta    = {};
        try { parsedPostingMeta = JSON.parse(safePostingMetaStr); } catch (e) {}
        try { parsedJsonMeta    = JSON.parse(safeJsonMetaStr); } catch (e) {}
        const profile = { ...(parsedJsonMeta.profile || {}), ...(parsedPostingMeta.profile || {}) };

        return {
            _entity_type: 'account',
            _sanitized: true,
            _stored_at: Date.now(),
            _profile: {
                display_name: typeof profile.name === 'string' ? profile.name.slice(0, 64) : null,
                about: typeof profile.about === 'string' ? profile.about.slice(0, 512) : null,
                location: typeof profile.location === 'string' ? profile.location.slice(0, 128) : null,
                website: typeof profile.website === 'string' ? profile.website.slice(0, 256) : null,
                profile_image: profile.profile_image || null,
                cover_image: profile.cover_image || null,
            },
            _links: [],
            // SECURITY FIX (v3.5.2): Apply validators to legacy path
            name: this.contentSanitizer.sanitizeUsername(account.name) || '',
            id: VALIDATORS.safe_number(account.id) ?? 0,
            json_metadata:         safeJsonMetaStr,
            posting_json_metadata: safePostingMetaStr,
            reputation:       VALIDATORS.safe_number(account.reputation) ?? 0,
            reputation_score: this.formatter.reputation(account.reputation),
            balance: translateAssetFromChain(VALIDATORS.safe_asset(account.balance) || '0.000 PXA'),
            vesting_shares: translateAssetFromChain(VALIDATORS.safe_asset(account.vesting_shares) || '0.000000 PXP'),
            voting_power: VALIDATORS.safe_number(account.voting_power) ?? 0,
            post_count: VALIDATORS.safe_number(account.post_count) ?? 0,
            created: VALIDATORS.safe_timestamp(account.created),
        };
    }

    /**
     * Process a post through pixa-content WASM sanitizer
     * Returns the post object enriched with sanitized HTML, images, links.
     * v3.4.0: Uses SanitizationPipeline if available; returns already-sanitized entities as-is.
     *
     * @param {object} post - Raw post object from blockchain
     * @param {object} [renderOptions] - Override render options (include_images, max_image_count, internal_domains)
     * @returns {object|null} Processed post with html, images, links, wordCount
     */
    processPost(post, renderOptions = {}) {
        if (!post) return null;

        // SECURITY PATCH (v3.5.2-patched): Require sanitizer — fail-closed
        if (!this.sanitizerReady) {
            throw new PixaAPIError('Cannot process post: content sanitizer not ready', 'SANITIZER_NOT_READY');
        }

        // v3.5.2: Re-validate _sanitized flag — IndexedDB data can be tampered
        if (post._sanitized && post._entity_type === 'post' && post._stored_at &&
            (Date.now() - post._stored_at) < (this.config.ENTITY_TTL?.posts || 300000)) {
            return post;
        }

        if (this.sanitizationPipeline) {
            return this.sanitizationPipeline.sanitizePost(post, renderOptions);
        }

        // Legacy fallback — build field-by-field, NO spread of raw data.
        const processed = this.contentSanitizer.renderPost(post.body || '', renderOptions);
        const safeMetaStr = this.contentSanitizer.safeJson(post.json_metadata || '{}');
        let meta = {};
        try { meta = JSON.parse(safeMetaStr); } catch (e) {}
        return {
            _entity_type: 'post',
            _sanitized: true,
            _stored_at: Date.now(),
            _images: processed.images || [],
            _links: processed.links || [],
            _summary: this.contentSanitizer.extractPlainText(post.body || '').slice(0, 500),
            _word_count: processed.wordCount || 0,
            id: post.id || 0,
            author: post.author || '',
            permlink: post.permlink || '',
            title: post.title || '',
            body: processed.html || '',
            json_metadata: safeMetaStr,
            category: post.category || '',
            parent_author: post.parent_author || '',
            parent_permlink: post.parent_permlink || '',
            created: VALIDATORS.safe_timestamp(post.created),
            last_update: VALIDATORS.safe_timestamp(post.last_update),
            active: VALIDATORS.safe_timestamp(post.active),
            cashout_time: VALIDATORS.safe_timestamp(post.cashout_time),
            last_payout: VALIDATORS.safe_timestamp(post.last_payout),
            depth: post.depth ?? 0,
            children: post.children ?? 0,
            net_votes: post.net_votes ?? 0,
            author_reputation: this.formatter.reputation(post.author_reputation),
            pending_payout_value: translateAssetFromChain(post.pending_payout_value || '0.000 PXS'),
            total_payout_value: translateAssetFromChain(post.total_payout_value || '0.000 PXS'),
            curator_payout_value: translateAssetFromChain(post.curator_payout_value || '0.000 PXS'),
            url: post.url || '',
        };
    }

    /**
     * Process a comment through pixa-content WASM sanitizer (stricter subset)
     * No headings, tables, or iframes allowed in comments.
     * v3.4.0: Uses SanitizationPipeline if available.
     *
     * @param {object} comment - Raw comment object from blockchain
     * @param {object} [renderOptions] - Override render options
     * @returns {object|null} Processed comment with html, images, links
     */
    processComment(comment, renderOptions = {}) {
        if (!comment) return null;

        // SECURITY PATCH (v3.5.2-patched): Require sanitizer — fail-closed
        if (!this.sanitizerReady) {
            throw new PixaAPIError('Cannot process comment: content sanitizer not ready', 'SANITIZER_NOT_READY');
        }

        // v3.5.2: Re-validate _sanitized flag
        if (comment._sanitized && comment._entity_type === 'comment' && comment._stored_at &&
            (Date.now() - comment._stored_at) < (this.config.ENTITY_TTL?.comments || 300000)) {
            return comment;
        }

        if (this.sanitizationPipeline) {
            return this.sanitizationPipeline.sanitizeComment(comment, renderOptions);
        }

        // Legacy fallback — build field-by-field, NO spread of raw data.
        const processed = this.contentSanitizer.renderComment(comment.body || '', renderOptions);
        const safeMetaStr = this.contentSanitizer.safeJson(comment.json_metadata || '{}');
        let meta = {};
        try { meta = JSON.parse(safeMetaStr); } catch (e) {}
        return {
            _entity_type: 'comment',
            _sanitized: true,
            _stored_at: Date.now(),
            _images: processed.images || [],
            _links: processed.links || [],
            _word_count: processed.wordCount || 0,
            id: comment.id || 0,
            author: comment.author || '',
            permlink: comment.permlink || '',
            title: '',
            body: processed.html || '',
            json_metadata: safeMetaStr,
            parent_author: comment.parent_author || '',
            parent_permlink: comment.parent_permlink || '',
            created: VALIDATORS.safe_timestamp(comment.created),
            last_update: VALIDATORS.safe_timestamp(comment.last_update),
            active: VALIDATORS.safe_timestamp(comment.active),
            cashout_time: VALIDATORS.safe_timestamp(comment.cashout_time),
            last_payout: VALIDATORS.safe_timestamp(comment.last_payout),
            depth: comment.depth ?? 1,
            children: comment.children ?? 0,
            net_votes: comment.net_votes ?? 0,
            author_reputation: this.formatter.reputation(comment.author_reputation),
            pending_payout_value: translateAssetFromChain(comment.pending_payout_value || '0.000 PXS'),
            total_payout_value: translateAssetFromChain(comment.total_payout_value || '0.000 PXS'),
            curator_payout_value: translateAssetFromChain(comment.curator_payout_value || '0.000 PXS'),
            root_author: comment.root_author || '',
            root_permlink: comment.root_permlink || '',
            url: comment.url || '',
        };
    }

    /**
     * Process a transaction memo for display.
     * Bold, italic, @mentions, #hashtags only. No images, lists, or blocks.
     * v0.2: New method using sanitizeMemo tier.
     *
     * @param {string} memo - Raw memo string
     * @returns {{ html: string }} Sanitized memo
     */
    processMemo(memo) {
        if (!memo) return { html: '' };
        return this.contentSanitizer.renderMemo(memo);
    }

    /**
     * Extract clean plain text from a post/comment body
     * Strips all HTML/Markdown formatting.
     *
     * @param {string} body - Raw body content
     * @returns {string} Clean plain text
     */
    extractPlainText(body) {
        return this.contentSanitizer.extractPlainText(body || '');
    }

    /**
     * TF-IDF extractive summarization of content
     *
     * @param {string} body - Raw body content
     * @param {number} [sentenceCount=3] - Number of top sentences to extract
     * @returns {{ summary: string, keywords: Array, sentences: Array }}
     */
    summarizeContent(body, sentenceCount = 3) {
        return this.contentSanitizer.summarize(body || '', sentenceCount);
    }

    /**
     * Validate and sanitize a username (HIVE-compatible: 3-16 chars, a-z0-9.-)
     *
     * @param {string} rawUsername
     * @returns {string} Sanitized username, or '' if invalid
     */
    sanitizeUsername(rawUsername) {
        return this.contentSanitizer.sanitizeUsername(rawUsername);
    }

    /**
     * Get current active account
     * @returns {Promise<string|null>}
     */
    async getActiveAccount() {
        return this.sessionManager?.getActiveAccount() || null;
    }

    /**
     * Check if user is logged in with valid session
     * @returns {Promise<boolean>}
     */
    async isLoggedIn() {
        const account = await this.sessionManager?.getActiveAccount();
        if (!account) return false;
        return this.sessionManager.isSessionValid(account);
    }

    /**
     * Subscribe to events
     * @param {string} event
     * @param {Function} callback
     */
    on(event, callback) {
        this.eventEmitter.on(event, callback);
        return this;
    }

    /**
     * Unsubscribe from events
     * @param {string} event
     * @param {Function} callback
     */
    off(event, callback) {
        this.eventEmitter.off(event, callback);
        return this;
    }

    /**
     * Subscribe to event once
     * @param {string} event
     * @param {Function} callback
     */
    once(event, callback) {
        this.eventEmitter.once(event, callback);
        return this;
    }
}

// ============================================
// Database API Group
// ============================================

class DatabaseAPI {
    constructor(proxy) { this.proxy = proxy; }

    async call(method, params = []) {
        return this.proxy.client.call('condenser_api', method, params);
    }

    async getDatabaseInfo() {
        return this.call('get_database_info');
    }
}

// ============================================
// Tags API Group
// ============================================

class TagsAPI {
    constructor(proxy) { this.proxy = proxy; }

    /**
     * Internal: Fetch discussions through entity store + query cache.
     * @param {string} sort - Sort category (trending, created, hot, etc.)
     * @param {object} query - Query parameters { tag, limit, start_author, start_permlink }
     * @returns {Promise<object[]>} Sanitized discussions
     * @private
     */
    async _fetchDiscussions(sort, query) {
        const q = {
            tag: query.tag || '',
            limit: parseInt(query.limit, 10) || 20
        };
        if (query.start_author) q.start_author = query.start_author;
        if (query.start_permlink) q.start_permlink = query.start_permlink;

        const queryKey = QueryCacheManager.buildKey(sort, q);

        // v3.4.0: Check query cache → resolve from entity store
        if (this.proxy.queryCache && this.proxy.entityStore) {
            const cached = await this.proxy.queryCache.get(queryKey, sort);
            if (cached) {
                const type = cached.entity_type || 'posts';
                const resolved = await this.proxy.entityStore.resolve(type, cached.ids);
                const allFresh = resolved.every(r => r !== null);
                if (allFresh) return resolved;
            }
        }

        let rawResults = null;

        try {
            rawResults = await this.proxy.client.database.getDiscussions(sort, q);
        } catch (e) {
            console.warn(`[TagsAPI] getDiscussions(${sort}) failed:`, e.message);
        }

        if (!rawResults || !Array.isArray(rawResults)) return [];

        // Sanitize, store entities, cache query as ID array
        if (this.proxy.sanitizationPipeline && this.proxy.entityStore && this.proxy.queryCache) {
            const ids = [];
            for (const raw of rawResults) {
                const entity = this.proxy.sanitizationPipeline.sanitizeContent(raw);
                if (entity) {
                    const type = entity._entity_type === 'post' ? 'posts' : 'comments';
                    await this.proxy.entityStore.upsert(type, entity);
                    ids.push(entity._entity_id);
                }
            }
            // Store query → ID[] mapping
            await this.proxy.queryCache.store(queryKey, ids, 'posts');
            // Resolve from store (ensures consistent sanitized output)
            const resolved = await this.proxy.entityStore.resolve('posts', ids);
            return resolved.filter(Boolean);
        }

        // SECURITY PATCH (v3.5.2-patched): FAIL-CLOSED — never return raw unsanitized data
        console.error('[TagsAPI] Sanitizer pipeline not available — refusing to serve raw content');
        return [];
    }

    async getTrendingTags(afterTag = '', limit = 100) {
        try {
            return await this.proxy.client.call('condenser_api', 'get_trending_tags', [afterTag, limit]);
        } catch (e) {
            console.warn('[TagsAPI] get_trending_tags failed:', e.message);
        }
        return [];
    }

    async getDiscussionsByTrending(query) {
        return this._fetchDiscussions('trending', query);
    }

    async getDiscussionsByCreated(query) {
        return this._fetchDiscussions('created', query);
    }

    async getDiscussionsByHot(query) {
        return this._fetchDiscussions('hot', query);
    }

    async getDiscussionsByPromoted(query) {
        return this._fetchDiscussions('promoted', query);
    }

    async getDiscussionsByPayout(query) {
        return this._fetchDiscussions('cashout', { ...query, sort_mapped: 'cashout' });
    }

    async getDiscussionsByVotes(query) {
        return this._fetchDiscussions('votes', query);
    }

    async getDiscussionsByActive(query) {
        return this._fetchDiscussions('active', query);
    }

    async getDiscussionsByChildren(query) {
        return this._fetchDiscussions('children', query);
    }

    async getDiscussionsByMuted(query) {
        console.warn('[TagsAPI] getDiscussionsByMuted: muted sort not available in database API');
        return [];
    }
}

// ============================================
// Blocks API Group
// ============================================

class BlocksAPI {
    constructor(proxy) { this.proxy = proxy; }

    async getBlock(blockNum) {
        return this.proxy.client.database.getBlock(blockNum);
    }

    async getBlockHeader(blockNum) {
        return this.proxy.client.database.getBlockHeader(blockNum);
    }

    async getOpsInBlock(blockNum, onlyVirtual = false) {
        return this.proxy.client.database.getOperations(blockNum, onlyVirtual);
    }
}

// ============================================
// Globals API Group
// ============================================

class GlobalsAPI {
    constructor(proxy) { this.proxy = proxy; }

    async getDynamicGlobalProperties() {
        return this.proxy.client.database.getDynamicGlobalProperties();
    }

    async getChainProperties() {
        return this.proxy.client.database.getChainProperties();
    }

    async getFeedHistory() {
        return this.proxy.client.call('condenser_api', 'get_feed_history');
    }

    async getCurrentMedianHistoryPrice() {
        return this.proxy.client.database.getCurrentMedianHistoryPrice();
    }

    async getHardforkVersion() {
        return this.proxy.client.call('condenser_api', 'get_hardfork_version');
    }

    async getRewardFund(name = 'post') {
        return this.proxy.client.call('condenser_api', 'get_reward_fund', [name]);
    }

    async getVestingDelegations(account, from = '', limit = 100) {
        return this.proxy.client.database.getVestingDelegations(account, from, limit);
    }

    async getConfig() {
        return this.proxy.client.database.getConfig();
    }

    async getVersion() {
        return this.proxy.client.database.getVersion();
    }
}

// ============================================
// Accounts API Group
// ============================================

class AccountsAPI {
    constructor(proxy) { this.proxy = proxy; }

    async getAccounts(accounts, forceRefresh = false) {
        const normalizedAccounts = accounts.map(acc => normalizeAccount(acc)).filter(acc => acc && acc.length > 0);

        if (normalizedAccounts.length === 0) return [];

        // v3.4.0: Check entity store first (unless forced refresh)
        if (!forceRefresh && this.proxy.entityStore) {
            const cached = await this.proxy.entityStore.resolve('accounts', normalizedAccounts);
            const allFresh = cached.every(c => c !== null);
            if (allFresh) {
                return cached;
            }
        }

        // database.getAccounts(usernames) — documented dpixa method
        let rawAccounts = [];
        try {
            rawAccounts = await this.proxy.client.database.getAccounts(normalizedAccounts);
        } catch (e) {
            console.warn('[AccountsAPI] getAccounts failed:', e.message);
            return [];
        }

        // Sanitize and upsert into entity store
        if (this.proxy.sanitizationPipeline && this.proxy.entityStore) {
            const sanitized = [];
            for (const raw of rawAccounts) {
                if (!raw) continue;
                const entity = this.proxy.sanitizationPipeline.sanitizeAccount(raw);
                if (entity) {
                    await this.proxy.entityStore.upsert('accounts', entity);
                    sanitized.push(entity);
                }
            }
            return sanitized;
        }

        // SECURITY PATCH (v3.5.2-patched): FAIL-CLOSED — never return raw unsanitized data
        console.error('[AccountsAPI] Sanitizer pipeline not available — refusing to serve raw accounts');
        return [];
    }

    async lookupAccounts(lowerBound, limit = 10) {
        try {
            return await this.proxy.client.call('condenser_api', 'lookup_accounts', [lowerBound, limit]);
        } catch (e) {
            console.warn('[AccountsAPI] lookup_accounts failed:', e.message);
        }
        return [];
    }

    async lookupAccountNames(accounts) {
        try {
            return await this.proxy.client.call('condenser_api', 'lookup_account_names', [accounts]);
        } catch (e) {
            console.warn('[AccountsAPI] lookup_account_names failed:', e.message);
        }
        return [];
    }

    async getAccountCount() {
        try {
            return await this.proxy.client.call('condenser_api', 'get_account_count');
        } catch (e) {
            console.warn('[AccountsAPI] get_account_count failed:', e.message);
        }
        return 0;
    }

    async getAccountHistory(account, from = -1, limit = 100, operationBitmask = null) {
        const normalizedAccount = normalizeAccount(account);

        // HIVE API constraint: start must be >= limit - 1 (start is a reverse index).
        // Use -1 to request the most recent entries. For explicit indices,
        // clamp limit so the constraint is satisfied.
        let safeFrom = from;
        let safeLimit = limit;
        if (safeFrom !== -1 && safeFrom < safeLimit - 1) {
            safeLimit = safeFrom + 1;  // request only as many entries as available from that index
        }

        // database.getAccountHistory(account, from, limit, bitmask?) — documented dpixa method
        try {
            if (operationBitmask) {
                return await this.proxy.client.database.getAccountHistory(normalizedAccount, safeFrom, safeLimit, operationBitmask);
            }
            return await this.proxy.client.database.getAccountHistory(normalizedAccount, safeFrom, safeLimit);
        } catch (e) {
            console.warn('[AccountsAPI] getAccountHistory failed:', e.message);
        }
        return [];
    }

    async getAccountReputations(lowerBound = '', limit = 1000) {
        try {
            return await this.proxy.client.call('condenser_api', 'get_account_reputations', [lowerBound, limit]);
        } catch (e) {
            console.warn('[AccountsAPI] get_account_reputations failed:', e.message);
        }
        return [];
    }

    async getAccountNotifications(account, limit = 50) {
        const normalizedAccount = normalizeAccount(account);

        try {
            if (this.proxy.client.pixamind) {
                return await this.proxy.client.pixamind.getAccountNotifications({
                    account: normalizedAccount,
                    limit: limit
                });
            }
        } catch (e) {
            console.warn('[AccountsAPI] pixamind.getAccountNotifications failed:', e.message);
        }
        return [];
    }
}

// ============================================
// Market API Group
// ============================================

class MarketAPI {
    constructor(proxy) { this.proxy = proxy; }

    async getOrderBook(limit = 500) {
        return this.proxy.client.call('condenser_api', 'get_order_book', [limit]);
    }

    async getOpenOrders(account) {
        const normalizedAccount = normalizeAccount(account);
        return this.proxy.client.call('condenser_api', 'get_open_orders', [normalizedAccount]);
    }

    async getTicker() {
        return this.proxy.client.call('condenser_api', 'get_ticker');
    }

    async getTradeHistory(start, end, limit = 1000) {
        return this.proxy.client.call('condenser_api', 'get_trade_history', [start, end, limit]);
    }

    async getMarketHistory(bucketSeconds, start, end) {
        return this.proxy.client.call('condenser_api', 'get_market_history', [bucketSeconds, start, end]);
    }

    async getMarketHistoryBuckets() {
        return this.proxy.client.call('condenser_api', 'get_market_history_buckets');
    }
}

// ============================================
// Authority API Group
// ============================================

class AuthorityAPI {
    constructor(proxy) { this.proxy = proxy; }

    async getOwnerHistory(account) {
        const normalizedAccount = normalizeAccount(account);
        return this.proxy.client.call('condenser_api', 'get_owner_history', [normalizedAccount]);
    }

    async getRecoveryRequest(account) {
        const normalizedAccount = normalizeAccount(account);
        return this.proxy.client.call('condenser_api', 'get_recovery_request', [normalizedAccount]);
    }

    async getWithdrawRoutes(account, type = 'outgoing') {
        const normalizedAccount = normalizeAccount(account);
        return this.proxy.client.call('condenser_api', 'get_withdraw_routes', [normalizedAccount, type]);
    }

    async getAccountBandwidth(account, type) {
        const normalizedAccount = normalizeAccount(account);
        return this.proxy.client.call('condenser_api', 'get_account_bandwidth', [normalizedAccount, type]);
    }

    async getSavingsWithdrawFrom(account) {
        const normalizedAccount = normalizeAccount(account);
        return this.proxy.client.call('condenser_api', 'get_savings_withdraw_from', [normalizedAccount]);
    }

    async getSavingsWithdrawTo(account) {
        const normalizedAccount = normalizeAccount(account);
        return this.proxy.client.call('condenser_api', 'get_savings_withdraw_to', [normalizedAccount]);
    }

    async verifyAuthority(stx) {
        return this.proxy.client.database.verifyAuthority(stx);
    }
}

// ============================================
// Votes API Group
// ============================================

class VotesAPI {
    constructor(proxy) { this.proxy = proxy; }

    async getActiveVotes(author, permlink) {
        const normalizedAuthor = normalizeAccount(author);
        return this.proxy.client.call('condenser_api', 'get_active_votes', [normalizedAuthor, permlink]);
    }

    async getAccountVotes(account) {
        const normalizedAccount = normalizeAccount(account);
        return this.proxy.client.call('condenser_api', 'get_account_votes', [normalizedAccount]);
    }
}

// ============================================
// Content API Group
// ============================================

class ContentAPI {
    constructor(proxy) { this.proxy = proxy; }

    async getContent(author, permlink) {
        const normalizedAuthor = normalizeAccount(author);
        const entityId = `${normalizedAuthor}_${permlink}`;

        // v3.4.0: Check entity stores (posts first, then comments)
        if (this.proxy.entityStore) {
            const cachedPost = await this.proxy.entityStore.get('posts', entityId);
            if (cachedPost) return cachedPost;

            const cachedComment = await this.proxy.entityStore.get('comments', entityId);
            if (cachedComment) return cachedComment;
        }

        // Fetch from chain
        let raw = null;
        try {
            raw = await this.proxy.client.call('condenser_api', 'get_content', [normalizedAuthor, permlink]);
        } catch (e) {
            console.warn('[ContentAPI] get_content failed:', e.message);
            return null;
        }

        if (!raw || !raw.author) return null;

        // Sanitize and store
        if (this.proxy.sanitizationPipeline && this.proxy.entityStore) {
            const entity = this.proxy.sanitizationPipeline.sanitizeContent(raw);
            if (entity) {
                const type = entity._entity_type === 'post' ? 'posts' : 'comments';
                await this.proxy.entityStore.upsert(type, entity);
                return entity;
            }
        }

        // SECURITY PATCH (v3.5.2-patched): FAIL-CLOSED
        console.error('[ContentAPI] Sanitizer pipeline not available — refusing to serve raw content');
        return null;
    }

    async getContentReplies(author, permlink) {
        const normalizedAuthor = normalizeAccount(author);
        const queryKey = QueryCacheManager.buildKey('content_replies', { author: normalizedAuthor, permlink });

        // v3.4.0: Check query cache
        if (this.proxy.queryCache && this.proxy.entityStore) {
            const cached = await this.proxy.queryCache.get(queryKey, 'content_replies');
            if (cached) {
                const resolved = await this.proxy.entityStore.resolve('comments', cached.ids);
                const allFresh = resolved.every(r => r !== null);
                if (allFresh) return resolved;
            }
        }

        // Fetch from chain
        let rawReplies = [];
        try {
            rawReplies = await this.proxy.client.call('condenser_api', 'get_content_replies', [normalizedAuthor, permlink]);
        } catch (e) {
            console.warn('[ContentAPI] get_content_replies failed:', e.message);
            return [];
        }

        if (!rawReplies || !Array.isArray(rawReplies)) return [];

        // Sanitize, store entities, cache query
        if (this.proxy.sanitizationPipeline && this.proxy.entityStore && this.proxy.queryCache) {
            const ids = [];
            for (const raw of rawReplies) {
                const entity = this.proxy.sanitizationPipeline.sanitizeComment(raw);
                if (entity) {
                    await this.proxy.entityStore.upsert('comments', entity);
                    ids.push(entity._entity_id);
                }
            }
            await this.proxy.queryCache.store(queryKey, ids, 'comments');
            return (await this.proxy.entityStore.resolve('comments', ids)).filter(Boolean);
        }

        // SECURITY PATCH (v3.5.2-patched): FAIL-CLOSED
        console.error('[ContentAPI] Sanitizer pipeline not available — refusing to serve raw replies');
        return [];
    }

    async getDiscussionsByAuthorBeforeDate(author, startPermlink, beforeDate, limit = 10) {
        const normalizedAuthor = normalizeAccount(author);
        try {
            const rawResults = await this.proxy.client.call('condenser_api', 'get_discussions_by_author_before_date', [normalizedAuthor, startPermlink, beforeDate, limit]);

            // Sanitize and store
            if (rawResults && this.proxy.sanitizationPipeline && this.proxy.entityStore) {
                const sanitized = [];
                for (const raw of rawResults) {
                    const entity = this.proxy.sanitizationPipeline.sanitizeContent(raw);
                    if (entity) {
                        const type = entity._entity_type === 'post' ? 'posts' : 'comments';
                        await this.proxy.entityStore.upsert(type, entity);
                        sanitized.push(entity);
                    }
                }
                return sanitized;
            }
            // SECURITY PATCH (v3.5.2-patched): FAIL-CLOSED
            if (rawResults && rawResults.length > 0) {
                console.error('[ContentAPI] Sanitizer pipeline not available — refusing raw content');
            }
            return [];
        } catch (e) {
            console.warn('[ContentAPI] get_discussions_by_author_before_date failed:', e.message);
        }
        return [];
    }

    async getRepliesByLastUpdate(author, startPermlink = '', limit = 10) {
        const normalizedAuthor = normalizeAccount(author);
        if (!normalizedAuthor) return [];

        try {
            // get_discussions_by_comments uses start_author, not tag
            const q = { start_author: normalizedAuthor, limit };
            if (startPermlink) {
                q.start_permlink = startPermlink;
            }
            const rawResults = await this.proxy.client.database.getDiscussions('comments', q);

            // Sanitize and store as comments
            if (rawResults && this.proxy.sanitizationPipeline && this.proxy.entityStore) {
                const sanitized = [];
                for (const raw of rawResults) {
                    const entity = this.proxy.sanitizationPipeline.sanitizeComment(raw);
                    if (entity) {
                        await this.proxy.entityStore.upsert('comments', entity);
                        sanitized.push(entity);
                    }
                }
                return sanitized;
            }
            // SECURITY PATCH (v3.5.2-patched): FAIL-CLOSED
            if (rawResults && rawResults.length > 0) {
                console.error('[ContentAPI] Sanitizer pipeline not available — refusing raw replies');
            }
            return [];
        } catch (e) {
            console.warn('[ContentAPI] getRepliesByLastUpdate failed:', e.message);
        }
        return [];
    }

    /**
     * Internal: Fetch discussions through entity store + query cache with multi-strategy fallback.
     * Shared by getDiscussionsByComments, getDiscussionsByBlog, getDiscussionsByFeed.
     * @private
     */
    async _fetchDiscussionsWithCache(sort, query, entityType = 'posts') {
        const normalizedTag = normalizeAccount(query.tag || '');
        if (!normalizedTag) return [];

        const limit = parseInt(query.limit, 10) || 20;

        // dpixa passes the query object through to condenser_api.get_discussions_by_${sort}
        // get_discussions_by_comments does NOT accept "tag" — it uses start_author
        // get_discussions_by_blog / get_discussions_by_feed use "tag" as the username
        const q = { limit };
        if (sort === 'comments') {
            q.start_author = normalizedTag;
            if (query.start_permlink) q.start_permlink = query.start_permlink;
        } else {
            q.tag = normalizedTag;
            if (query.start_author) q.start_author = query.start_author;
            if (query.start_permlink) q.start_permlink = query.start_permlink;
        }

        const queryKey = QueryCacheManager.buildKey(`content_${sort}`, q);

        // v3.4.0: Check query cache → resolve from entity store
        if (this.proxy.queryCache && this.proxy.entityStore) {
            const cached = await this.proxy.queryCache.get(queryKey, sort);
            if (cached) {
                const resolved = await this.proxy.entityStore.resolve(cached.entity_type || entityType, cached.ids);
                if (resolved.every(r => r !== null)) return resolved;
            }
        }

        // Fetch from chain
        let rawResults = null;

        try {
            rawResults = await this.proxy.client.database.getDiscussions(sort, q);
        } catch (e) {
            console.warn(`[ContentAPI] getDiscussions(${sort}) failed:`, e.message);
        }

        if (!rawResults || !Array.isArray(rawResults)) return [];

        // Sanitize, store entities, cache query IDs
        if (this.proxy.sanitizationPipeline && this.proxy.entityStore && this.proxy.queryCache) {
            const ids = [];
            for (const raw of rawResults) {
                const entity = this.proxy.sanitizationPipeline.sanitizeContent(raw);
                if (entity) {
                    const storeType = entity._entity_type === 'post' ? 'posts' : 'comments';
                    await this.proxy.entityStore.upsert(storeType, entity);
                    ids.push(entity._entity_id);
                }
            }
            await this.proxy.queryCache.store(queryKey, ids, entityType);
            const resolved = await this.proxy.entityStore.resolve(entityType, ids);
            return resolved.filter(Boolean);
        }

        // SECURITY PATCH (v3.5.2-patched): FAIL-CLOSED
        console.error('[ContentAPI] Sanitizer pipeline not available — refusing to serve raw content');
        return [];
    }

    async getDiscussionsByComments(query) {
        const author = query.start_author || query.tag || '';
        const normalizedAuthor = normalizeAccount(author);
        if (!normalizedAuthor) return [];

        const q = {
            tag: normalizedAuthor,
            limit: parseInt(query.limit, 10) || 20
        };
        // Only include pagination cursor if both fields are present
        if (query.start_author) q.start_author = query.start_author;
        if (query.start_permlink) q.start_permlink = query.start_permlink;

        return this._fetchDiscussionsWithCache('comments', q, 'comments');
    }

    async getDiscussionsByBlog(query) {
        return this._fetchDiscussionsWithCache('blog', query, 'posts');
    }

    async getDiscussionsByFeed(query) {
        return this._fetchDiscussionsWithCache('feed', query, 'posts');
    }

    async getAccountPosts(account, sort = 'blog', limit = 20, options = {}) {
        const normalizedAccount = normalizeAccount(account);
        if (!normalizedAccount) return [];

        const q = {
            tag: normalizedAccount,
            limit: parseInt(limit, 10) || 20
        };
        if (options.start_author) q.start_author = options.start_author;
        if (options.start_permlink) q.start_permlink = options.start_permlink;

        return this._fetchDiscussionsWithCache(sort, q, sort === 'comments' ? 'comments' : 'posts');
    }

    async getState(path) {
        return this.proxy.client.database.getState(path);
    }
}

// ============================================
// Witnesses API Group
// ============================================

class WitnessesAPI {
    constructor(proxy) { this.proxy = proxy; }

    async getWitnessByAccount(account) {
        const normalizedAccount = normalizeAccount(account);
        return this.proxy.client.call('condenser_api', 'get_witness_by_account', [normalizedAccount]);
    }

    async getWitnessesByVote(from, limit = 100) {
        return this.proxy.client.call('condenser_api', 'get_witnesses_by_vote', [from, limit]);
    }

    async lookupWitnessAccounts(lowerBound, limit = 100) {
        return this.proxy.client.call('condenser_api', 'lookup_witness_accounts', [lowerBound, limit]);
    }

    async getWitnessCount() {
        return this.proxy.client.call('condenser_api', 'get_witness_count');
    }

    async getActiveWitnesses() {
        return this.proxy.client.call('condenser_api', 'get_active_witnesses');
    }

    async getWitnessSchedule() {
        return this.proxy.client.call('condenser_api', 'get_witness_schedule');
    }
}

// ============================================
// Follow API Group
// ============================================

class FollowAPI {
    constructor(proxy) { this.proxy = proxy; }

    async getFollowers(account, startFollower = null, type = 'blog', limit = 100) {
        const normalizedAccount = normalizeAccount(account);
        if (!normalizedAccount) return [];
        const safeLimit = parseInt(limit, 10) || 100;

        try {
            return await this.proxy.client.call('condenser_api', 'get_followers', [normalizedAccount, startFollower, type, safeLimit]);
        } catch (e) {
            console.warn('[FollowAPI] get_followers failed:', e.message);
        }
        return [];
    }

    async getFollowing(account, startFollowing = null, type = 'blog', limit = 100) {
        const normalizedAccount = normalizeAccount(account);
        if (!normalizedAccount) return [];
        const safeLimit = parseInt(limit, 10) || 100;

        try {
            return await this.proxy.client.call('condenser_api', 'get_following', [normalizedAccount, startFollowing, type, safeLimit]);
        } catch (e) {
            console.warn('[FollowAPI] get_following failed:', e.message);
        }
        return [];
    }

    async getFollowCount(account) {
        const normalizedAccount = normalizeAccount(account);
        if (!normalizedAccount) return { account: account || '', follower_count: 0, following_count: 0 };

        // database.getAccounts(usernames) — documented dpixa method, always has follower counts
        try {
            const accounts = await this.proxy.client.database.getAccounts([normalizedAccount]);
            if (accounts && accounts[0]) {
                const acc = accounts[0];
                return {
                    account: normalizedAccount,
                    follower_count: acc.follower_count || 0,
                    following_count: acc.following_count || 0
                };
            }
        } catch (e) {
            console.warn('[FollowAPI] getFollowCount failed:', e.message);
        }
        return { account: normalizedAccount, follower_count: 0, following_count: 0 };
    }

    async getFeedEntries(account, startEntryId = 0, limit = 10) {
        const normalizedAccount = normalizeAccount(account);

        try {
            return await this.proxy.client.call('condenser_api', 'get_feed_entries', [normalizedAccount, startEntryId, limit]);
        } catch (e) {
            console.warn('[FollowAPI] get_feed_entries failed:', e.message);
        }
        return [];
    }

    async getBlogEntries(account, startEntryId = 0, limit = 10) {
        const normalizedAccount = normalizeAccount(account);

        try {
            return await this.proxy.client.call('condenser_api', 'get_blog_entries', [normalizedAccount, startEntryId, limit]);
        } catch (e) {
            console.warn('[FollowAPI] get_blog_entries failed:', e.message);
        }
        return [];
    }

    async getRebloggedBy(author, permlink) {
        const normalizedAuthor = normalizeAccount(author);

        try {
            return await this.proxy.client.call('condenser_api', 'get_reblogged_by', [normalizedAuthor, permlink]);
        } catch (e) {
            console.warn('[FollowAPI] get_reblogged_by failed:', e.message);
        }
        return [];
    }

    async getBlogAuthors(account) {
        const normalizedAccount = normalizeAccount(account);

        try {
            return await this.proxy.client.call('condenser_api', 'get_blog_authors', [normalizedAccount]);
        } catch (e) {
            console.warn('[FollowAPI] get_blog_authors failed:', e.message);
        }
        return [];
    }

    async getSubscriptions(account) {
        const normalizedAccount = normalizeAccount(account);

        // No dpixa method exists for subscriptions — use client.call() raw RPC
        try {
            return await this.proxy.client.call('bridge', 'list_all_subscriptions', { account: normalizedAccount });
        } catch (e) {
            console.warn('[FollowAPI] list_all_subscriptions failed:', e.message);
        }
        return [];
    }
}

// ============================================
// Broadcast API Group
// ============================================

class BroadcastAPI {
    constructor(proxy) { this.proxy = proxy; }

    async updateAccount2(paramsOrAccount, jsonMetadata, postingJsonMetadata, extensions = []) {
        let params;
        if (typeof paramsOrAccount === 'object' && paramsOrAccount !== null && paramsOrAccount.account) {
            params = paramsOrAccount;
        } else {
            params = { account: paramsOrAccount, jsonMetadata, postingJsonMetadata, extensions };
        }

        const { account, auth = {} } = params;
        const normalizedAccount = normalizeAccount(account);

        if (!normalizedAccount) {
            throw new PixaAPIError('Invalid account parameter', 'INVALID_ACCOUNT');
        }

        const requiresActive = auth.owner || auth.active || auth.posting || auth.memo_key ||
            (params.jsonMetadata !== undefined && params.jsonMetadata !== null);

        const keyType = requiresActive ? 'active' : 'posting';
        const key = await this.proxy.keyManager.requestKey(normalizedAccount, keyType);

        const ensureString = (val) => {
            if (val === null || val === undefined) return "";
            if (typeof val === 'string') return val;
            try { return JSON.stringify(val); } catch (e) { return ""; }
        };

        const op = {
            account: normalizedAccount,
            json_metadata: ensureString(params.jsonMetadata),
            posting_json_metadata: ensureString(params.postingJsonMetadata),
            extensions: params.extensions || []
        };

        if (auth.owner) op.owner = auth.owner;
        if (auth.active) op.active = auth.active;
        if (auth.posting) op.posting = auth.posting;
        if (auth.memo_key) op.memo_key = auth.memo_key;

        return this.proxy.client.broadcast.sendOperations(
            [['account_update2', op]],
            PrivateKey.fromString(key)
        );
    }

    async updateProfile(account, profileObject) {
        const normalizedAccount = normalizeAccount(account);

        if (!normalizedAccount) {
            throw new PixaAPIError('Invalid account parameter', 'INVALID_ACCOUNT');
        }

        const [accountData] = await this.proxy.client.database.getAccounts([normalizedAccount]);
        if (!accountData) throw new PixaAPIError('Account not found', 'ACCOUNT_NOT_FOUND');

        let currentPostingMeta = {};
        try {
            if (accountData.posting_json_metadata) {
                currentPostingMeta = JSON.parse(accountData.posting_json_metadata);
            }
        } catch (e) {}

        const newPostingMeta = {
            ...currentPostingMeta,
            profile: { ...(currentPostingMeta.profile || {}), ...profileObject }
        };

        const result = await this.updateAccount2({
            account: normalizedAccount,
            jsonMetadata: accountData.json_metadata,
            postingJsonMetadata: newPostingMeta
        });

        if (this.proxy.eventEmitter) {
            this.proxy.eventEmitter.emit('profile_updated', { account: normalizedAccount, profile: newPostingMeta.profile });
        }

        return result;
    }

    async vote(voter, author, permlink, weight) {
        const normalizedVoter = normalizeAccount(voter);
        const normalizedAuthor = normalizeAccount(author);

        if (!normalizedVoter || !normalizedAuthor) {
            throw new PixaAPIError('Invalid account parameters', 'INVALID_ACCOUNT');
        }

        const key = await this.proxy.keyManager.requestKey(normalizedVoter, 'posting');
        const result = await this.proxy.client.broadcast.vote({
            voter: normalizedVoter,
            author: normalizedAuthor,
            permlink,
            weight
        }, PrivateKey.fromString(key));

        await this.proxy.cacheManager.invalidateKey('posts', `${normalizedAuthor}_${permlink}`);
        // v3.4.0: Invalidate entity stores
        if (this.proxy.entityStore) {
            await this.proxy.entityStore.invalidate('posts', `${normalizedAuthor}_${permlink}`);
            await this.proxy.entityStore.invalidate('comments', `${normalizedAuthor}_${permlink}`);
        }
        return result;
    }

    async comment(params) {
        const { parentAuthor = '', parentPermlink, author, permlink, title = '', body, jsonMetadata = {} } = params;
        const normalizedAuthor = normalizeAccount(author);
        const normalizedParentAuthor = parentAuthor ? normalizeAccount(parentAuthor) : '';

        if (!normalizedAuthor) {
            throw new PixaAPIError('Invalid author parameter', 'INVALID_ACCOUNT');
        }

        const key = await this.proxy.keyManager.requestKey(normalizedAuthor, 'posting');

        // Fix: Handle jsonMetadata properly to avoid double-stringify
        let metadataString;
        if (typeof jsonMetadata === 'string') {
            metadataString = jsonMetadata;
        } else {
            metadataString = JSON.stringify(jsonMetadata);
        }

        return this.proxy.client.broadcast.comment({
            parent_author: normalizedParentAuthor,
            parent_permlink: parentPermlink,
            author: normalizedAuthor,
            permlink,
            title,
            body,
            json_metadata: metadataString
        }, PrivateKey.fromString(key));
    }

    /**
     * Set comment options (beneficiaries, payout settings, etc.)
     * @param {object} params
     */
    async commentOptions(params) {
        const { author, permlink, maxAcceptedPayout, percentPxs, allowVotes, allowCurationRewards, extensions } = params;
        const normalizedAuthor = normalizeAccount(author);

        if (!normalizedAuthor) {
            throw new PixaAPIError('Invalid author parameter', 'INVALID_ACCOUNT');
        }

        const key = await this.proxy.keyManager.requestKey(normalizedAuthor, 'posting');

        const op = {
            author: normalizedAuthor,
            permlink,
            max_accepted_payout: translateAssetToChain(maxAcceptedPayout || '1000000.000 PXS'),
            percent_pxs: percentPxs !== undefined ? percentPxs : 10000,
            allow_votes: allowVotes !== undefined ? allowVotes : true,
            allow_curation_rewards: allowCurationRewards !== undefined ? allowCurationRewards : true,
            extensions: extensions || []
        };

        return this.proxy.client.broadcast.sendOperations(
            [['comment_options', op]],
            PrivateKey.fromString(key)
        );
    }

    async transfer(from, to, amount, memo = '') {
        const normalizedFrom = normalizeAccount(from);
        const normalizedTo = normalizeAccount(to);

        if (!normalizedFrom || !normalizedTo) {
            throw new PixaAPIError('Invalid account parameters', 'INVALID_ACCOUNT');
        }

        // SECURITY FIX (v3.5.2): Validate amount format before broadcasting
        if (!VALIDATORS.safe_asset(amount)) {
            throw new PixaAPIError('Invalid amount format', 'INVALID_AMOUNT');
        }

        const key = await this.proxy.keyManager.requestKey(normalizedFrom, 'active');
        return this.proxy.client.broadcast.transfer({
            from: normalizedFrom,
            to: normalizedTo,
            amount: translateAssetToChain(amount),
            memo
        }, PrivateKey.fromString(key));
    }

    /**
     * Power up (transfer to vesting)
     * @param {string} from - Source account
     * @param {string} to - Destination account (can be same or different)
     * @param {string} amount - Amount in PXA (e.g., "100.000 PXA")
     */
    async transferToVesting(from, to, amount) {
        const normalizedFrom = normalizeAccount(from);
        const normalizedTo = normalizeAccount(to) || normalizedFrom;

        if (!normalizedFrom) {
            throw new PixaAPIError('Invalid from account', 'INVALID_ACCOUNT');
        }

        // SECURITY FIX (v3.5.2): Validate amount format before broadcasting
        if (!VALIDATORS.safe_asset(amount)) {
            throw new PixaAPIError('Invalid amount format', 'INVALID_AMOUNT');
        }

        const key = await this.proxy.keyManager.requestKey(normalizedFrom, 'active');
        return this.proxy.client.broadcast.sendOperations(
            [['transfer_to_vesting', {
                from: normalizedFrom,
                to: normalizedTo,
                amount: translateAssetToChain(amount)
            }]],
            PrivateKey.fromString(key)
        );
    }

    /**
     * Power down (withdraw vesting)
     * @param {string} account - Account to power down
     * @param {string} vestingShares - Amount in PXP (e.g., "1000000.000000 PXP"), use "0.000000 PXP" to cancel
     */
    async withdrawVesting(account, vestingShares) {
        const normalizedAccount = normalizeAccount(account);

        if (!normalizedAccount) {
            throw new PixaAPIError('Invalid account', 'INVALID_ACCOUNT');
        }

        // SECURITY FIX (v3.5.2): Validate amount format before broadcasting
        if (!VALIDATORS.safe_asset(vestingShares)) {
            throw new PixaAPIError('Invalid vesting shares format', 'INVALID_AMOUNT');
        }

        const key = await this.proxy.keyManager.requestKey(normalizedAccount, 'active');
        return this.proxy.client.broadcast.sendOperations(
            [['withdraw_vesting', {
                account: normalizedAccount,
                vesting_shares: translateAssetToChain(vestingShares)
            }]],
            PrivateKey.fromString(key)
        );
    }

    /**
     * Delegate vesting shares
     * @param {string} delegator - Account delegating
     * @param {string} delegatee - Account receiving delegation
     * @param {string} vestingShares - Amount in PXP (use "0.000000 PXP" to undelegate)
     */
    async delegateVestingShares(delegator, delegatee, vestingShares) {
        const normalizedDelegator = normalizeAccount(delegator);
        const normalizedDelegatee = normalizeAccount(delegatee);

        if (!normalizedDelegator || !normalizedDelegatee) {
            throw new PixaAPIError('Invalid account parameters', 'INVALID_ACCOUNT');
        }

        // SECURITY FIX (v3.5.2): Validate amount format before broadcasting
        if (!VALIDATORS.safe_asset(vestingShares)) {
            throw new PixaAPIError('Invalid vesting shares format', 'INVALID_AMOUNT');
        }

        const key = await this.proxy.keyManager.requestKey(normalizedDelegator, 'active');
        return this.proxy.client.broadcast.sendOperations(
            [['delegate_vesting_shares', {
                delegator: normalizedDelegator,
                delegatee: normalizedDelegatee,
                vesting_shares: translateAssetToChain(vestingShares)
            }]],
            PrivateKey.fromString(key)
        );
    }

    /**
     * Transfer to savings
     */
    async transferToSavings(from, to, amount, memo = '') {
        const normalizedFrom = normalizeAccount(from);
        const normalizedTo = normalizeAccount(to);

        if (!normalizedFrom || !normalizedTo) {
            throw new PixaAPIError('Invalid account parameters', 'INVALID_ACCOUNT');
        }

        // SECURITY FIX (v3.5.2): Validate amount format before broadcasting
        if (!VALIDATORS.safe_asset(amount)) {
            throw new PixaAPIError('Invalid amount format', 'INVALID_AMOUNT');
        }

        const key = await this.proxy.keyManager.requestKey(normalizedFrom, 'active');
        return this.proxy.client.broadcast.sendOperations(
            [['transfer_to_savings', {
                from: normalizedFrom,
                to: normalizedTo,
                amount: translateAssetToChain(amount),
                memo
            }]],
            PrivateKey.fromString(key)
        );
    }

    /**
     * Transfer from savings (initiates 3-day withdrawal)
     */
    async transferFromSavings(from, requestId, to, amount, memo = '') {
        const normalizedFrom = normalizeAccount(from);
        const normalizedTo = normalizeAccount(to);

        if (!normalizedFrom || !normalizedTo) {
            throw new PixaAPIError('Invalid account parameters', 'INVALID_ACCOUNT');
        }

        // SECURITY FIX (v3.5.2): Validate amount format before broadcasting
        if (!VALIDATORS.safe_asset(amount)) {
            throw new PixaAPIError('Invalid amount format', 'INVALID_AMOUNT');
        }

        const key = await this.proxy.keyManager.requestKey(normalizedFrom, 'active');
        return this.proxy.client.broadcast.sendOperations(
            [['transfer_from_savings', {
                from: normalizedFrom,
                request_id: requestId,
                to: normalizedTo,
                amount: translateAssetToChain(amount),
                memo
            }]],
            PrivateKey.fromString(key)
        );
    }

    /**
     * Cancel pending savings withdrawal
     */
    async cancelTransferFromSavings(from, requestId) {
        const normalizedFrom = normalizeAccount(from);

        if (!normalizedFrom) {
            throw new PixaAPIError('Invalid account', 'INVALID_ACCOUNT');
        }

        const key = await this.proxy.keyManager.requestKey(normalizedFrom, 'active');
        return this.proxy.client.broadcast.sendOperations(
            [['cancel_transfer_from_savings', {
                from: normalizedFrom,
                request_id: requestId
            }]],
            PrivateKey.fromString(key)
        );
    }

    /**
     * Claim pending rewards
     * @param {string} account - Account claiming rewards
     * @param {string} rewardPixa - PXA reward to claim (e.g., "1.000 PXA")
     * @param {string} rewardPxs - PXS reward to claim (e.g., "0.500 PXS")
     * @param {string} rewardVests - PXP reward to claim (e.g., "100.000000 PXP")
     */
    async claimRewardBalance(account, rewardPixa, rewardPxs, rewardVests) {
        const normalizedAccount = normalizeAccount(account);

        if (!normalizedAccount) {
            throw new PixaAPIError('Invalid account', 'INVALID_ACCOUNT');
        }

        // SECURITY FIX (v3.5.2): Validate amount formats before broadcasting
        if (!VALIDATORS.safe_asset(rewardPixa) || !VALIDATORS.safe_asset(rewardPxs) || !VALIDATORS.safe_asset(rewardVests)) {
            throw new PixaAPIError('Invalid reward amount format', 'INVALID_AMOUNT');
        }

        const key = await this.proxy.keyManager.requestKey(normalizedAccount, 'posting');
        return this.proxy.client.broadcast.claimRewardBalance({
            account: normalizedAccount,
            reward_pixa: translateAssetToChain(rewardPixa),
            reward_pxs: translateAssetToChain(rewardPxs),
            reward_vests: translateAssetToChain(rewardVests)
        }, PrivateKey.fromString(key));
    }

    /**
     * Set up recurring transfer
     * @param {object} params
     */
    async recurrentTransfer(params) {
        const { from, to, amount, memo = '', recurrence, executions } = params;
        const normalizedFrom = normalizeAccount(from);
        const normalizedTo = normalizeAccount(to);

        if (!normalizedFrom || !normalizedTo) {
            throw new PixaAPIError('Invalid account parameters', 'INVALID_ACCOUNT');
        }

        const key = await this.proxy.keyManager.requestKey(normalizedFrom, 'active');
        return this.proxy.client.broadcast.sendOperations(
            [['recurrent_transfer', {
                from: normalizedFrom,
                to: normalizedTo,
                amount: translateAssetToChain(amount),
                memo,
                recurrence, // Hours between transfers
                executions, // Number of transfers (0 to cancel)
                extensions: []
            }]],
            PrivateKey.fromString(key)
        );
    }

    async follow(follower, following) {
        const normalizedFollower = normalizeAccount(follower);
        const normalizedFollowing = normalizeAccount(following);

        if (!normalizedFollower || !normalizedFollowing) {
            throw new PixaAPIError('Invalid account parameters', 'INVALID_ACCOUNT');
        }

        const key = await this.proxy.keyManager.requestKey(normalizedFollower, 'posting');
        return this.proxy.client.broadcast.sendOperations(
            [['custom_json', {
                required_auths: [],
                required_posting_auths: [normalizedFollower],
                id: 'follow',
                json: JSON.stringify(['follow', { follower: normalizedFollower, following: normalizedFollowing, what: ['blog'] }])
            }]],
            PrivateKey.fromString(key)
        );
    }

    async unfollow(follower, following) {
        const normalizedFollower = normalizeAccount(follower);
        const normalizedFollowing = normalizeAccount(following);

        if (!normalizedFollower || !normalizedFollowing) {
            throw new PixaAPIError('Invalid account parameters', 'INVALID_ACCOUNT');
        }

        const key = await this.proxy.keyManager.requestKey(normalizedFollower, 'posting');
        return this.proxy.client.broadcast.sendOperations(
            [['custom_json', {
                required_auths: [],
                required_posting_auths: [normalizedFollower],
                id: 'follow',
                json: JSON.stringify(['follow', { follower: normalizedFollower, following: normalizedFollowing, what: [] }])
            }]],
            PrivateKey.fromString(key)
        );
    }

    /**
     * Mute a user
     */
    async mute(follower, following) {
        const normalizedFollower = normalizeAccount(follower);
        const normalizedFollowing = normalizeAccount(following);

        if (!normalizedFollower || !normalizedFollowing) {
            throw new PixaAPIError('Invalid account parameters', 'INVALID_ACCOUNT');
        }

        const key = await this.proxy.keyManager.requestKey(normalizedFollower, 'posting');
        return this.proxy.client.broadcast.sendOperations(
            [['custom_json', {
                required_auths: [],
                required_posting_auths: [normalizedFollower],
                id: 'follow',
                json: JSON.stringify(['follow', { follower: normalizedFollower, following: normalizedFollowing, what: ['ignore'] }])
            }]],
            PrivateKey.fromString(key)
        );
    }

    async reblog(account, author, permlink) {
        const normalizedAccount = normalizeAccount(account);
        const normalizedAuthor = normalizeAccount(author);

        if (!normalizedAccount || !normalizedAuthor) {
            throw new PixaAPIError('Invalid account parameters', 'INVALID_ACCOUNT');
        }

        const key = await this.proxy.keyManager.requestKey(normalizedAccount, 'posting');
        return this.proxy.client.broadcast.sendOperations(
            [['custom_json', {
                required_auths: [],
                required_posting_auths: [normalizedAccount],
                id: 'follow',
                json: JSON.stringify(['reblog', { account: normalizedAccount, author: normalizedAuthor, permlink }])
            }]],
            PrivateKey.fromString(key)
        );
    }

    /**
     * Broadcast a custom_json operation
     * @param {object} params - { requiredAuths, requiredPostingAuths, id, json }
     * @param {object} [auths] - Optional override keys. When provided, bypasses
     *   keyManager and uses the supplied WIF directly.
     *   Shape: { active: '<wif>', posting: '<wif>' }
     */
    async customJson(params, auths) {
        const { requiredAuths = [], requiredPostingAuths = [], id, json } = params;
        const signingAccount = requiredAuths[0] || requiredPostingAuths[0];
        const keyType = requiredAuths.length > 0 ? 'active' : 'posting';

        let key;
        if (auths && auths[keyType]) {
            key = auths[keyType];
        } else {
            key = await this.proxy.keyManager.requestKey(normalizeAccount(signingAccount), keyType);
        }

        return this.proxy.client.broadcast.sendOperations(
            [['custom_json', {
                required_auths: requiredAuths.map(a => normalizeAccount(a)),
                required_posting_auths: requiredPostingAuths.map(a => normalizeAccount(a)),
                id,
                json: typeof json === 'string' ? json : JSON.stringify(json)
            }]],
            PrivateKey.fromString(key)
        );
    }

    async deleteComment(author, permlink) {
        const normalizedAuthor = normalizeAccount(author);

        if (!normalizedAuthor) {
            throw new PixaAPIError('Invalid author', 'INVALID_ACCOUNT');
        }

        const key = await this.proxy.keyManager.requestKey(normalizedAuthor, 'posting');
        return this.proxy.client.broadcast.sendOperations(
            [['delete_comment', { author: normalizedAuthor, permlink }]],
            PrivateKey.fromString(key)
        );
    }

    /**
     * Create a new account
     * @param {object} params
     */
    async accountCreate(params) {
        const { fee, creator, newAccountName, owner, active, posting, memoKey, jsonMetadata = '{}' } = params;
        const normalizedCreator = normalizeAccount(creator);
        const normalizedNewAccount = normalizeAccount(newAccountName);

        if (!normalizedCreator || !normalizedNewAccount) {
            throw new PixaAPIError('Invalid account parameters', 'INVALID_ACCOUNT');
        }

        const key = await this.proxy.keyManager.requestKey(normalizedCreator, 'active');
        return this.proxy.client.broadcast.sendOperations(
            [['account_create', {
                fee: translateAssetToChain(fee),
                creator: normalizedCreator,
                new_account_name: normalizedNewAccount,
                owner,
                active,
                posting,
                memo_key: memoKey,
                json_metadata: typeof jsonMetadata === 'string' ? jsonMetadata : JSON.stringify(jsonMetadata)
            }]],
            PrivateKey.fromString(key)
        );
    }

    /**
     * Create account with delegation
     */
    async accountCreateWithDelegation(params) {
        const { fee, delegation, creator, newAccountName, owner, active, posting, memoKey, jsonMetadata = '{}', extensions = [] } = params;
        const normalizedCreator = normalizeAccount(creator);
        const normalizedNewAccount = normalizeAccount(newAccountName);

        if (!normalizedCreator || !normalizedNewAccount) {
            throw new PixaAPIError('Invalid account parameters', 'INVALID_ACCOUNT');
        }

        const key = await this.proxy.keyManager.requestKey(normalizedCreator, 'active');
        return this.proxy.client.broadcast.sendOperations(
            [['account_create_with_delegation', {
                fee: translateAssetToChain(fee),
                delegation: translateAssetToChain(delegation),
                creator: normalizedCreator,
                new_account_name: normalizedNewAccount,
                owner,
                active,
                posting,
                memo_key: memoKey,
                json_metadata: typeof jsonMetadata === 'string' ? jsonMetadata : JSON.stringify(jsonMetadata),
                extensions
            }]],
            PrivateKey.fromString(key)
        );
    }

    /**
     * Vote for a witness
     */
    async accountWitnessVote(account, witness, approve = true) {
        const normalizedAccount = normalizeAccount(account);
        const normalizedWitness = normalizeAccount(witness);

        if (!normalizedAccount || !normalizedWitness) {
            throw new PixaAPIError('Invalid account parameters', 'INVALID_ACCOUNT');
        }

        const key = await this.proxy.keyManager.requestKey(normalizedAccount, 'active');
        return this.proxy.client.broadcast.sendOperations(
            [['account_witness_vote', {
                account: normalizedAccount,
                witness: normalizedWitness,
                approve
            }]],
            PrivateKey.fromString(key)
        );
    }

    /**
     * Set witness proxy
     */
    async accountWitnessProxy(account, proxy) {
        const normalizedAccount = normalizeAccount(account);
        const normalizedProxy = proxy ? normalizeAccount(proxy) : '';

        if (!normalizedAccount) {
            throw new PixaAPIError('Invalid account', 'INVALID_ACCOUNT');
        }

        const key = await this.proxy.keyManager.requestKey(normalizedAccount, 'active');
        return this.proxy.client.broadcast.sendOperations(
            [['account_witness_proxy', {
                account: normalizedAccount,
                proxy: normalizedProxy
            }]],
            PrivateKey.fromString(key)
        );
    }

    /**
     * Update witness
     */
    async witnessUpdate(params) {
        const { owner, url, blockSigningKey, props, fee } = params;
        const normalizedOwner = normalizeAccount(owner);

        if (!normalizedOwner) {
            throw new PixaAPIError('Invalid owner account', 'INVALID_ACCOUNT');
        }

        const key = await this.proxy.keyManager.requestKey(normalizedOwner, 'active');
        return this.proxy.client.broadcast.sendOperations(
            [['witness_update', {
                owner: normalizedOwner,
                url,
                block_signing_key: blockSigningKey,
                props,
                fee: translateAssetToChain(fee)
            }]],
            PrivateKey.fromString(key)
        );
    }

    /**
     * Set withdraw vesting route (for power down distribution)
     */
    async setWithdrawVestingRoute(fromAccount, toAccount, percent, autoVest = false) {
        const normalizedFrom = normalizeAccount(fromAccount);
        const normalizedTo = normalizeAccount(toAccount);

        if (!normalizedFrom || !normalizedTo) {
            throw new PixaAPIError('Invalid account parameters', 'INVALID_ACCOUNT');
        }

        const key = await this.proxy.keyManager.requestKey(normalizedFrom, 'active');
        return this.proxy.client.broadcast.sendOperations(
            [['set_withdraw_vesting_route', {
                from_account: normalizedFrom,
                to_account: normalizedTo,
                percent, // 0-10000 (basis points)
                auto_vest: autoVest
            }]],
            PrivateKey.fromString(key)
        );
    }

    /**
     * Create limit order on internal market
     */
    async limitOrderCreate(params) {
        const { owner, orderId, amountToSell, minToReceive, fillOrKill = false, expiration } = params;
        const normalizedOwner = normalizeAccount(owner);

        if (!normalizedOwner) {
            throw new PixaAPIError('Invalid owner account', 'INVALID_ACCOUNT');
        }

        const key = await this.proxy.keyManager.requestKey(normalizedOwner, 'active');
        return this.proxy.client.broadcast.sendOperations(
            [['limit_order_create', {
                owner: normalizedOwner,
                orderid: orderId,
                amount_to_sell: translateAssetToChain(amountToSell),
                min_to_receive: translateAssetToChain(minToReceive),
                fill_or_kill: fillOrKill,
                expiration: expiration || new Date(Date.now() + 28 * 24 * 60 * 60 * 1000).toISOString().slice(0, -5)
            }]],
            PrivateKey.fromString(key)
        );
    }

    /**
     * Cancel limit order
     */
    async limitOrderCancel(owner, orderId) {
        const normalizedOwner = normalizeAccount(owner);

        if (!normalizedOwner) {
            throw new PixaAPIError('Invalid owner account', 'INVALID_ACCOUNT');
        }

        const key = await this.proxy.keyManager.requestKey(normalizedOwner, 'active');
        return this.proxy.client.broadcast.sendOperations(
            [['limit_order_cancel', {
                owner: normalizedOwner,
                orderid: orderId
            }]],
            PrivateKey.fromString(key)
        );
    }

    /**
     * Convert PXA to PXS
     */
    async convertPixa(owner, amount, requestId) {
        const normalizedOwner = normalizeAccount(owner);

        if (!normalizedOwner) {
            throw new PixaAPIError('Invalid owner account', 'INVALID_ACCOUNT');
        }

        // SECURITY FIX (v3.5.2): Validate amount format before broadcasting
        if (!VALIDATORS.safe_asset(amount)) {
            throw new PixaAPIError('Invalid amount format', 'INVALID_AMOUNT');
        }

        const key = await this.proxy.keyManager.requestKey(normalizedOwner, 'active');
        return this.proxy.client.broadcast.sendOperations(
            [['convert', {
                owner: normalizedOwner,
                amount: translateAssetToChain(amount),
                requestid: requestId
            }]],
            PrivateKey.fromString(key)
        );
    }

    /**
     * Send raw operations
     * @param {Array} operations - Array of [opType, opData] tuples
     * @param {PrivateKey|string} key - Private key for signing
     */
    async sendOperations(operations, key) {
        const privateKey = typeof key === 'string' ? PrivateKey.fromString(key) : key;
        return this.proxy.client.broadcast.sendOperations(operations, privateKey);
    }
}

// ============================================
// Auth API Group
// ============================================

class AuthAPI {
    constructor(proxy) { this.proxy = proxy; }

    isWif(key) {
        try {
            PrivateKey.fromString(key);
            return true;
        } catch (e) {
            return false;
        }
    }

    toWif(username, password, role) {
        return PrivateKey.fromLogin(username, password, role).toString();
    }

    wifToPublic(wif) {
        return PrivateKey.fromString(wif).createPublic().toString();
    }

    signMessage(message, wif) {
        const privateKey = PrivateKey.fromString(wif);
        const signature = privateKey.sign(cryptoUtils.sha256(message));
        return signature.toString();
    }

    verifySignature(message, signature, publicKey) {
        try {
            const sig = Signature.fromString(signature);
            const pubKey = PublicKey.fromString(publicKey);
            return sig.verify(cryptoUtils.sha256(message), pubKey);
        } catch (e) {
            return false;
        }
    }

    /**
     * Encode a memo for private messaging
     * @param {string} senderPrivateKey - Sender's private memo key (WIF)
     * @param {string} recipientPublicKey - Recipient's public memo key
     * @param {string} message - Message to encrypt
     * @returns {string} Encrypted memo (starts with #)
     */
    encodeMemo(senderPrivateKey, recipientPublicKey, message) {
        const privateKey = PrivateKey.fromString(senderPrivateKey);
        return Memo.encode(privateKey, recipientPublicKey, message);
    }

    /**
     * Decode an encrypted memo
     * @param {string} recipientPrivateKey - Recipient's private memo key (WIF)
     * @param {string} encryptedMemo - Encrypted memo (starts with #)
     * @returns {string} Decrypted message
     */
    decodeMemo(recipientPrivateKey, encryptedMemo) {
        const privateKey = PrivateKey.fromString(recipientPrivateKey);
        return Memo.decode(privateKey, encryptedMemo);
    }

    /**
     * Generate keys from username and password
     * @param {string} username
     * @param {string} password
     * @returns {object} Object with owner, active, posting, memo keys
     */
    generateKeys(username, password) {
        const normalizedUsername = normalizeAccount(username);
        return {
            owner: PrivateKey.fromLogin(normalizedUsername, password, 'owner').toString(),
            ownerPublic: PrivateKey.fromLogin(normalizedUsername, password, 'owner').createPublic().toString(),
            active: PrivateKey.fromLogin(normalizedUsername, password, 'active').toString(),
            activePublic: PrivateKey.fromLogin(normalizedUsername, password, 'active').createPublic().toString(),
            posting: PrivateKey.fromLogin(normalizedUsername, password, 'posting').toString(),
            postingPublic: PrivateKey.fromLogin(normalizedUsername, password, 'posting').createPublic().toString(),
            memo: PrivateKey.fromLogin(normalizedUsername, password, 'memo').toString(),
            memoPublic: PrivateKey.fromLogin(normalizedUsername, password, 'memo').createPublic().toString()
        };
    }
}

// ============================================
// Formatter API Group
// ============================================

class FormatterAPI {
    constructor(proxy) { this.proxy = proxy; }

    reputation(rawReputation) {
        if (!rawReputation || rawReputation === 0) return 25;
        const neg = rawReputation < 0;
        const rep = Math.log10(Math.abs(rawReputation));
        let score = Math.max(rep - 9, 0) * 9 + 25;
        if (neg) score = 50 - score;
        return Math.round(score * 100) / 100;
    }

    vestToPixa(vestingShares, totalVestingShares, totalVestingFundPixa) {
        return (parseFloat(vestingShares) / parseFloat(totalVestingShares)) * parseFloat(totalVestingFundPixa);
    }

    pixaToVest(pixa, totalVestingShares, totalVestingFundPixa) {
        return (parseFloat(pixa) / parseFloat(totalVestingFundPixa)) * parseFloat(totalVestingShares);
    }

    /** @deprecated Use vestToPixa() */
    vestToSteem(...args) { return this.vestToPixa(...args); }
    /** @deprecated Use pixaToVest() */
    steemToVest(...args) { return this.pixaToVest(...args); }

    formatAsset(amount, symbol, precision = 3) {
        return `${parseFloat(amount).toFixed(precision)} ${symbol}`;
    }

    /**
     * Calculate vesting share price from dynamic global properties
     * @param {object} props - Dynamic global properties
     * @returns {Price}
     */
    getVestingSharePrice(props) {
        return getVestingSharePrice(props);
    }

    /**
     * Get effective vesting shares for an account
     * @param {object} account - Account object
     * @param {boolean} subtractDelegated - Subtract delegated VESTS
     * @param {boolean} addReceived - Add received VESTS
     * @returns {number}
     */
    getVests(account, subtractDelegated = true, addReceived = true) {
        return getVests(account, subtractDelegated, addReceived);
    }
}

// ============================================
// Blockchain API Group (with streaming)
// ============================================

class BlockchainAPI {
    constructor(proxy) {
        this.proxy = proxy;
        this.BLOCK_INTERVAL = 3000; // 3 seconds
    }

    async getBlockHeader(blockNum) {
        return this.proxy.client.database.getBlockHeader(blockNum);
    }

    async getBlock(blockNum) {
        return this.proxy.client.database.getBlock(blockNum);
    }

    async getTransaction(txId) {
        return this.proxy.client.database.getTransaction(txId);
    }

    async getTransactionHex(tx) {
        return this.proxy.client.call('condenser_api', 'get_transaction_hex', [tx]);
    }

    /**
     * Get current block number
     * @param {string} mode - 'irreversible' or 'latest'
     * @returns {Promise<number>}
     */
    async getCurrentBlockNum(mode = 'irreversible') {
        const props = await this.proxy.client.database.getDynamicGlobalProperties();
        if (mode === 'latest' || mode === BlockchainMode?.Latest) {
            return props.head_block_number;
        }
        return props.last_irreversible_block_num;
    }

    /**
     * Get current block header
     * @param {string} mode - 'irreversible' or 'latest'
     */
    async getCurrentBlockHeader(mode = 'irreversible') {
        const blockNum = await this.getCurrentBlockNum(mode);
        return this.getBlockHeader(blockNum);
    }

    /**
     * Get current full block
     * @param {string} mode - 'irreversible' or 'latest'
     */
    async getCurrentBlock(mode = 'irreversible') {
        const blockNum = await this.getCurrentBlockNum(mode);
        return this.getBlock(blockNum);
    }

    /**
     * Async generator for block numbers
     * @param {object} options - { from, to, mode }
     * @yields {number}
     */
    async *getBlockNumbers(options = {}) {
        const { from, to, mode = 'irreversible' } = options;

        let currentBlock = from !== undefined ? from : await this.getCurrentBlockNum(mode);
        const endBlock = to;

        while (true) {
            const headBlock = await this.getCurrentBlockNum(mode);

            while (currentBlock <= headBlock && (endBlock === undefined || currentBlock <= endBlock)) {
                yield currentBlock;
                currentBlock++;
            }

            if (endBlock !== undefined && currentBlock > endBlock) {
                return;
            }

            // Wait for next block
            await new Promise(resolve => setTimeout(resolve, this.BLOCK_INTERVAL));
        }
    }

    /**
     * Async generator for full blocks
     * @param {object} options - { from, to, mode }
     * @yields {SignedBlock}
     */
    async *getBlocks(options = {}) {
        for await (const blockNum of this.getBlockNumbers(options)) {
            const block = await this.getBlock(blockNum);
            if (block) {
                yield block;
            }
        }
    }

    /**
     * Async generator for operations (including virtual)
     * @param {object} options - { from, to, mode }
     * @yields {AppliedOperation}
     */
    async *getOperations(options = {}) {
        for await (const blockNum of this.getBlockNumbers(options)) {
            const ops = await this.proxy.blocks.getOpsInBlock(blockNum, false);
            for (const op of ops) {
                yield op;
            }
        }
    }

    /**
     * Get block number stream (Node.js Readable)
     * @param {object} options
     * @returns {ReadableStream}
     */
    getBlockNumberStream(options = {}) {
        const iterator = this.getBlockNumbers(options);
        return this._iteratorToStream(iterator);
    }

    /**
     * Get block stream (Node.js Readable)
     * @param {object} options
     * @returns {ReadableStream}
     */
    getBlockStream(options = {}) {
        const iterator = this.getBlocks(options);
        return this._iteratorToStream(iterator);
    }

    /**
     * Get operations stream (Node.js Readable)
     * @param {object} options
     * @returns {ReadableStream}
     */
    getOperationsStream(options = {}) {
        const iterator = this.getOperations(options);
        return this._iteratorToStream(iterator);
    }

    /**
     * Convert async iterator to readable stream
     * @private
     */
    _iteratorToStream(iterator) {
        // Check if we're in Node.js environment
        if (typeof require !== 'undefined') {
            try {
                const { Readable } = require('stream');
                return Readable.from(iterator);
            } catch (e) {
                console.warn('[BlockchainAPI] Stream conversion not available in browser');
            }
        }

        // Return the iterator itself if streams aren't available
        return iterator;
    }
}

// ============================================
// Resource Credits API Group
// ============================================

class ResourceCreditsAPI {
    constructor(proxy) { this.proxy = proxy; }

    async getResourceParams() {
        // No dpixa method — client.call() raw RPC
        return this.proxy.client.call('rc_api', 'get_resource_params', {});
    }

    async getResourcePool() {
        // No dpixa method — client.call() raw RPC
        return this.proxy.client.call('rc_api', 'get_resource_pool', {});
    }

    async findRcAccounts(accounts) {
        const normalizedAccounts = accounts.map(acc => normalizeAccount(acc)).filter(acc => acc && acc.length > 0);
        // rc.findRCAccounts(usernames) — documented dpixa method
        return this.proxy.client.rc.findRCAccounts(normalizedAccounts);
    }

    async getRCMana(account) {
        const normalizedAccount = normalizeAccount(account);
        // rc.getRCMana(username) — documented dpixa method
        return this.proxy.client.rc.getRCMana(normalizedAccount);
    }

    async getVPMana(account) {
        const normalizedAccount = normalizeAccount(account);
        // rc.getVPMana(username) — documented dpixa method
        return this.proxy.client.rc.getVPMana(normalizedAccount);
    }

    /**
     * Estimate RC cost for an operation
     * @param {string} operationType - e.g., 'vote', 'comment', 'transfer'
     * @param {object} operationData - Operation parameters
     */
    async calculateRCCost(operationType, operationData = {}) {
        // This is a simplified estimation - actual cost depends on current RC pool state
        const baseCosts = {
            vote: 20000000,
            comment: 150000000,
            transfer: 10000000,
            custom_json: 5000000,
            claim_reward_balance: 5000000,
            delegate_vesting_shares: 10000000,
            transfer_to_vesting: 10000000,
            withdraw_vesting: 10000000
        };

        const baseCost = baseCosts[operationType] || 50000000;

        // Adjust for content size if applicable
        if (operationType === 'comment' && operationData.body) {
            const bodySize = operationData.body.length;
            return baseCost + (bodySize * 10000);
        }

        if (operationType === 'custom_json' && operationData.json) {
            const jsonSize = typeof operationData.json === 'string'
                ? operationData.json.length
                : JSON.stringify(operationData.json).length;
            return baseCost + (jsonSize * 5000);
        }

        return baseCost;
    }
}

// ============================================
// Communities API Group
// ============================================

class CommunitiesAPI {
    constructor(proxy) { this.proxy = proxy; }

    async getCommunity(name, observer = '') {
        // pixamind.getCommunity({name}) — documented dpixa method
        try {
            if (this.proxy.client.pixamind) {
                return await this.proxy.client.pixamind.getCommunity({ name });
            }
        } catch (e) {
            console.warn('[CommunitiesAPI] getCommunity failed:', e.message);
        }
        return null;
    }

    async listCommunities(options = {}) {
        // No dpixa method — client.call() raw RPC
        try {
            return await this.proxy.client.call('bridge', 'list_communities', {
                last: options.last || '',
                limit: options.limit || 100,
                query: options.query || null,
                sort: options.sort || 'rank',
                observer: options.observer || ''
            });
        } catch (e) {
            console.warn('[CommunitiesAPI] listCommunities failed:', e.message);
        }
        return [];
    }

    async getSubscriptions(account) {
        const normalizedAccount = normalizeAccount(account);

        // No dpixa method — client.call() raw RPC
        try {
            return await this.proxy.client.call('bridge', 'list_all_subscriptions', { account: normalizedAccount });
        } catch (e) {
            console.warn('[CommunitiesAPI] getSubscriptions failed:', e.message);
        }
        return [];
    }

    async getRankedPosts(options = {}) {
        const sort = options.sort || 'trending';
        const validSorts = ['trending', 'created', 'hot', 'promoted', 'active', 'votes', 'children', 'cashout'];
        const dbSort = validSorts.includes(sort) ? sort : 'trending';

        const q = {
            tag: options.tag || '',
            limit: parseInt(options.limit, 10) || 20
        };
        if (options.start_author) q.start_author = options.start_author;
        if (options.start_permlink) q.start_permlink = options.start_permlink;

        const queryKey = QueryCacheManager.buildKey(`community_ranked_${dbSort}`, q);

        if (this.proxy.queryCache && this.proxy.entityStore) {
            const cached = await this.proxy.queryCache.get(queryKey, dbSort);
            if (cached) {
                const resolved = await this.proxy.entityStore.resolve(cached.entity_type || 'posts', cached.ids);
                if (resolved.every(r => r !== null)) return resolved;
            }
        }

        // pixamind.getRankedPosts({sort, tag, limit}) — documented dpixa method
        let rawResults = null;

        try {
            rawResults = await this.proxy.client.pixamind.getRankedPosts({
                sort: dbSort, tag: q.tag || '', limit: q.limit
            });
        } catch (e) {
            console.warn(`[CommunitiesAPI] getRankedPosts(${dbSort}) failed:`, e.message);
        }

        if (!rawResults || !Array.isArray(rawResults)) return [];

        if (this.proxy.sanitizationPipeline && this.proxy.entityStore && this.proxy.queryCache) {
            const ids = [];
            for (const raw of rawResults) {
                const entity = this.proxy.sanitizationPipeline.sanitizeContent(raw);
                if (entity) {
                    const type = entity._entity_type === 'post' ? 'posts' : 'comments';
                    await this.proxy.entityStore.upsert(type, entity);
                    ids.push(entity._entity_id);
                }
            }
            await this.proxy.queryCache.store(queryKey, ids, 'posts');
            return (await this.proxy.entityStore.resolve('posts', ids)).filter(Boolean);
        }

        console.error('[CommunitiesAPI] Sanitizer pipeline not available — refusing to serve raw content');
        return [];
    }

    async getAccountPosts(account, sort = 'blog', options = {}) {
        const normalizedAccount = normalizeAccount(account);

        const validSorts = ['blog', 'feed', 'comments', 'trending', 'created', 'hot', 'promoted', 'active', 'votes', 'children', 'cashout'];
        const dbSort = validSorts.includes(sort) ? sort : 'blog';

        // get_discussions_by_comments uses start_author; blog/feed/others use tag
        const q = { limit: parseInt(options.limit, 10) || 20 };
        if (dbSort === 'comments') {
            q.start_author = normalizedAccount;
            if (options.start_permlink) q.start_permlink = options.start_permlink;
        } else {
            q.tag = normalizedAccount;
            if (options.start_author) q.start_author = options.start_author;
            if (options.start_permlink) q.start_permlink = options.start_permlink;
        }

        const entityType = sort === 'comments' ? 'comments' : 'posts';
        const queryKey = QueryCacheManager.buildKey(`community_account_${dbSort}`, q);

        if (this.proxy.queryCache && this.proxy.entityStore) {
            const cached = await this.proxy.queryCache.get(queryKey, sort);
            if (cached) {
                const resolved = await this.proxy.entityStore.resolve(cached.entity_type || entityType, cached.ids);
                if (resolved.every(r => r !== null)) return resolved;
            }
        }

        // database.getDiscussions(by, query) — documented dpixa method, handles all sorts
        let rawResults = null;

        try {
            rawResults = await this.proxy.client.database.getDiscussions(dbSort, q);
        } catch (e) {
            console.warn(`[CommunitiesAPI] getAccountPosts(${dbSort}) failed:`, e.message);
        }

        if (!rawResults || !Array.isArray(rawResults)) return [];

        // Sanitize, store, cache
        if (this.proxy.sanitizationPipeline && this.proxy.entityStore && this.proxy.queryCache) {
            const ids = [];
            for (const raw of rawResults) {
                const entity = this.proxy.sanitizationPipeline.sanitizeContent(raw);
                if (entity) {
                    const storeType = entity._entity_type === 'post' ? 'posts' : 'comments';
                    await this.proxy.entityStore.upsert(storeType, entity);
                    ids.push(entity._entity_id);
                }
            }
            await this.proxy.queryCache.store(queryKey, ids, entityType);
            return (await this.proxy.entityStore.resolve(entityType, ids)).filter(Boolean);
        }

        // SECURITY PATCH (v3.5.2-patched): FAIL-CLOSED
        console.error('[CommunitiesAPI] Sanitizer pipeline not available — refusing to serve raw content');
        return [];
    }
}

// ============================================
// Account By Key API Group
// ============================================

class AccountByKeyAPI {
    constructor(proxy) { this.proxy = proxy; }

    /**
     * Find accounts associated with public keys
     * @param {Array<string|PublicKey>} keys - Array of public keys
     * @returns {Promise<{accounts: string[][]}>} - accounts[i] contains accounts for keys[i]
     */
    async getKeyReferences(keys) {
        const keyStrings = keys.map(k => {
            if (typeof k === 'string') return k;
            if (k instanceof PublicKey) return k.toString();
            return String(k);
        });

        try {
            // keys.getKeyReferences(keys) — documented dpixa method
            return await this.proxy.client.keys.getKeyReferences(keyStrings);
        } catch (e) {
            console.warn('[AccountByKeyAPI] getKeyReferences failed:', e.message);
        }

        return { accounts: keys.map(() => []) };
    }

    /**
     * Find account for a single key
     * @param {string|PublicKey} key
     * @returns {Promise<string[]>}
     */
    async findAccountsByKey(key) {
        const result = await this.getKeyReferences([key]);
        return result.accounts[0] || [];
    }
}

// ============================================
// Transaction Status API Group
// ============================================

class TransactionStatusAPI {
    constructor(proxy) { this.proxy = proxy; }

    /**
     * Find transaction status
     * @param {string} transactionId - Transaction ID (40-char hex)
     * @param {string} expiration - Optional expiration time
     * @returns {Promise<{status: string, block_num?: number}>}
     */
    async findTransaction(transactionId, expiration = null) {
        try {
            const params = { transaction_id: transactionId };
            if (expiration) params.expiration = expiration;

            return await this.proxy.client.call('transaction_status_api', 'find_transaction', params);
        } catch (e) {
            console.warn('[TransactionStatusAPI] find_transaction failed:', e.message);

            // Fallback: Try to find in recent blocks
            try {
                const tx = await this.proxy.client.database.getTransaction(transactionId);
                if (tx) {
                    return { status: 'within_irreversible_block' };
                }
            } catch (e2) {}

            return { status: 'unknown' };
        }
    }

    /**
     * Check if a transaction has been confirmed
     * @param {string} transactionId
     * @returns {Promise<boolean>}
     */
    async isConfirmed(transactionId) {
        const result = await this.findTransaction(transactionId);
        const confirmedStatuses = ['within_irreversible_block', 'within_reversible_block'];
        return confirmedStatuses.includes(result.status);
    }
}

// ============================================
// Internal Managers
// ============================================

class CacheManager {
    constructor(db) { this.db = db; this.collections = new Map(); }

    async getCollection(name) {
        if (!this.collections.has(name)) {
            this.collections.set(name, await this.db.getCollection(name));
        }
        return this.collections.get(name);
    }

    async get(collectionName, key, ttl) {
        try {
            const collection = await this.getCollection(collectionName);
            const doc = await collection.get(key);
            if (doc && doc.timestamp && (Date.now() - doc.timestamp) < ttl) {
                return doc.data;
            }
        } catch (e) {}
        return null;
    }

    async set(collectionName, key, data) {
        try {
            const collection = await this.getCollection(collectionName);
            const doc = { data, timestamp: Date.now() };
            try { await collection.add(doc, { id: key }); }
            catch (e) { await collection.update(key, doc); }
        } catch (e) {}
    }

    async invalidateKey(collectionName, key) {
        try {
            const collection = await this.getCollection(collectionName);
            await collection.delete(key);
        } catch (e) {}
    }

    async invalidateAll(collectionName) {
        try {
            const collection = await this.getCollection(collectionName);
            const docs = await collection.find({});
            for (const doc of docs) {
                try { await collection.delete(doc._id || doc.id); } catch (e) {}
            }
        } catch (e) {}
    }
}

class PaginationManager {
    constructor() { this.cursors = new Map(); }
    setCursor(key, cursor) { this.cursors.set(key, cursor); }
    getCursor(key) { return this.cursors.get(key); }
    clearCursor(key) { this.cursors.delete(key); }
    clearAll() { this.cursors.clear(); }
}

// ============================================
// Entity-Based Storage System (v3.4.0)
// ============================================

/**
 * SanitizationPipeline - Processes raw blockchain entities through
 * the ContentSanitizer before they enter the database.
 * Nothing enters entity stores unsanitized.
 */
class SanitizationPipeline {
    /**
     * @param {ContentSanitizer} sanitizer
     * @param {FormatterAPI} formatter
     */
    constructor(sanitizer, formatter) {
        this.sanitizer = sanitizer;
        this.formatter = formatter;
    }

    // ── ACCOUNT ─────────────────────────────────────────────────────────

    /**
     * Sanitize a raw account object for storage.
     * DANGEROUS FIELDS (`json_metadata`, `posting_json_metadata`) keep their
     * original names but store the WASM-parsed safe object — never the raw string.
     * All dates are integer millisecond timestamps (`new Date(ts)` ready).
     *
     * @param {object} raw - Raw account from blockchain RPC
     * @returns {object|null} Sanitized account ready for DB insertion
     */
    sanitizeAccount(raw) {
        if (!raw || !raw.name) return null;

        const name = this.sanitizer.sanitizeUsername(raw.name);
        if (!name) return null;

        // DANGEROUS: sanitize raw JSON strings through WASM, store sanitized strings only
        const rawPostingMeta = raw.posting_json_metadata || '{}';
        const rawJsonMeta    = raw.json_metadata || '{}';
        const safePostingMetaStr = this.sanitizer.safeJson(rawPostingMeta);
        const safeJsonMetaStr    = this.sanitizer.safeJson(rawJsonMeta);

        // Parse the safe strings locally for field extraction only
        let postingMeta = {};
        let jsonMeta    = {};
        try { postingMeta = JSON.parse(safePostingMetaStr); } catch (e) {}
        try { jsonMeta    = JSON.parse(safeJsonMetaStr); } catch (e) {}

        // Merge profile: posting_json_metadata takes priority
        const profile = { ...(jsonMeta.profile || {}), ...(postingMeta.profile || {}) };

        // Profile fields are already sanitized by safeJson (HTML stripped, schemes checked)
        const displayName  = typeof profile.name     === 'string' ? profile.name.slice(0, 64)  : null;
        const about        = typeof profile.about    === 'string' ? profile.about.slice(0, 512) : null;
        const location     = typeof profile.location === 'string' ? profile.location.slice(0, 128) : null;
        const website      = typeof profile.website  === 'string' ? profile.website.slice(0, 256) : null;
        const profileImage = typeof profile.profile_image === 'string' ? profile.profile_image : null;
        const coverImage   = typeof profile.cover_image   === 'string' ? profile.cover_image   : null;

        const links = [];
        if (website)      links.push(website);
        if (profileImage) links.push(profileImage);
        if (coverImage)   links.push(coverImage);

        // Build entity FIELD BY FIELD — no { ...raw } spread.
        return {
            _entity_id:   name,
            _entity_type: 'account',
            _sanitized:   true,
            _stored_at:   Date.now(),

            // Enrichment
            _profile: { display_name: displayName, about, location, website, profile_image: profileImage, cover_image: coverImage },
            _links: links,

            // Identity
            name,
            id: VALIDATORS.safe_number(raw.id) ?? 0,

            // DANGEROUS fields — keep names, store sanitized JSON strings
            json_metadata:         safeJsonMetaStr,
            posting_json_metadata: safePostingMetaStr,

            // Authority objects (structured chain data, not user text)
            owner:   VALIDATORS.safe_authority(raw.owner),
            active:  VALIDATORS.safe_authority(raw.active),
            posting: VALIDATORS.safe_authority(raw.posting),

            // Reputation
            reputation:       VALIDATORS.safe_number(raw.reputation) ?? 0,
            reputation_score: this.formatter ? this.formatter.reputation(raw.reputation) : 25,

            // Balances (translate chain symbols → display symbols)
            balance:                  translateAssetFromChain(VALIDATORS.safe_asset(raw.balance) || '0.000 PXA'),
            savings_balance:          translateAssetFromChain(VALIDATORS.safe_asset(raw.savings_balance) || '0.000 PXA'),
            pxs_balance:              translateAssetFromChain(VALIDATORS.safe_asset(raw.pxs_balance) || '0.000 PXS'),
            savings_pxs_balance:      translateAssetFromChain(VALIDATORS.safe_asset(raw.savings_pxs_balance) || '0.000 PXS'),
            vesting_shares:           translateAssetFromChain(VALIDATORS.safe_asset(raw.vesting_shares) || '0.000000 PXP'),
            delegated_vesting_shares: translateAssetFromChain(VALIDATORS.safe_asset(raw.delegated_vesting_shares) || '0.000000 PXP'),
            received_vesting_shares:  translateAssetFromChain(VALIDATORS.safe_asset(raw.received_vesting_shares) || '0.000000 PXP'),
            vesting_withdraw_rate:    translateAssetFromChain(VALIDATORS.safe_asset(raw.vesting_withdraw_rate) || '0.000000 PXP'),
            reward_pixa_balance:      translateAssetFromChain(VALIDATORS.safe_asset(raw.reward_pixa_balance) || '0.000 PXA'),
            reward_pxs_balance:       translateAssetFromChain(VALIDATORS.safe_asset(raw.reward_pxs_balance) || '0.000 PXS'),
            reward_vesting_balance:   translateAssetFromChain(VALIDATORS.safe_asset(raw.reward_vesting_balance) || '0.000000 PXP'),
            reward_vesting_pixa:      translateAssetFromChain(VALIDATORS.safe_asset(raw.reward_vesting_pixa) || '0.000 PXA'),
            post_voting_power:        translateAssetFromChain(VALIDATORS.safe_asset(raw.post_voting_power) || '0.000000 PXP'),

            // Voting / mana
            voting_power:    VALIDATORS.safe_number(raw.voting_power) ?? 0,
            voting_manabar:  VALIDATORS.safe_manabar(raw.voting_manabar),
            downvote_manabar: VALIDATORS.safe_manabar(raw.downvote_manabar),
            can_vote:        VALIDATORS.safe_bool(raw.can_vote) ?? true,

            // Activity counts
            post_count:          VALIDATORS.safe_number(raw.post_count) ?? 0,
            curation_rewards:    VALIDATORS.safe_number(raw.curation_rewards) ?? 0,
            posting_rewards:     VALIDATORS.safe_number(raw.posting_rewards) ?? 0,
            witnesses_voted_for: VALIDATORS.safe_number(raw.witnesses_voted_for) ?? 0,

            // Timestamps (integer ms — `new Date(ts)`)
            created:             VALIDATORS.safe_timestamp(raw.created),
            last_post:           VALIDATORS.safe_timestamp(raw.last_post),
            last_root_post:      VALIDATORS.safe_timestamp(raw.last_root_post),
            last_vote_time:      VALIDATORS.safe_timestamp(raw.last_vote_time),
            last_account_update: VALIDATORS.safe_timestamp(raw.last_account_update),
            last_owner_update:   VALIDATORS.safe_timestamp(raw.last_owner_update),

            // Power down
            next_vesting_withdrawal: VALIDATORS.safe_timestamp(raw.next_vesting_withdrawal),
            withdrawn:               VALIDATORS.safe_number(raw.withdrawn) ?? 0,
            to_withdraw:             VALIDATORS.safe_number(raw.to_withdraw) ?? 0,
            withdraw_routes:         VALIDATORS.safe_number(raw.withdraw_routes) ?? 0,

            // Savings
            savings_withdraw_requests: VALIDATORS.safe_number(raw.savings_withdraw_requests) ?? 0,

            // Governance
            witness_votes: Array.isArray(raw.witness_votes)
                ? raw.witness_votes.filter(w => typeof w === 'string' && w.length <= 16)
                : [],
            proxied_vsf_votes: Array.isArray(raw.proxied_vsf_votes)
                ? raw.proxied_vsf_votes.map(v => String(v))
                : [],

            // Keys / proxy / recovery
            memo_key:         VALIDATORS.safe_pubkey(raw.memo_key) || '',
            proxy:            raw.proxy ? (this.sanitizer.sanitizeUsername(raw.proxy) || '') : '',
            recovery_account: raw.recovery_account ? (this.sanitizer.sanitizeUsername(raw.recovery_account) || '') : '',
        };
    }

    // ── POST ────────────────────────────────────────────────────────────

    /**
     * Sanitize a raw post (root-level content, depth=0) for storage.
     * `body` stores sanitized HTML (raw markdown is discarded).
     * `json_metadata` keeps its name but stores the WASM-parsed safe object.
     * All dates are integer millisecond timestamps.
     *
     * @param {object} raw - Raw discussion/post from blockchain RPC
     * @param {object} [renderOptions]
     * @returns {object|null} Sanitized post ready for DB insertion
     */
    sanitizePost(raw, renderOptions = {}) {
        if (!raw || !raw.author || !raw.permlink) return null;

        const author   = this.sanitizer.sanitizeUsername(raw.author);
        const permlink = VALIDATORS.safe_permlink(raw.permlink);
        if (!author || !permlink) return null;

        const entityId = `${author}_${permlink}`;

        // DANGEROUS: body — sanitize through WASM, store only sanitized HTML
        const rendered = this.sanitizer.renderPost(raw.body || '', renderOptions);

        // DANGEROUS: json_metadata — sanitize through WASM, store as safe string
        const safeMetaStr = this.sanitizer.safeJson(raw.json_metadata || '{}');
        let meta = {};
        try { meta = JSON.parse(safeMetaStr); } catch (e) {}

        // Build entity FIELD BY FIELD — no { ...raw } spread.
        return {
            _entity_id:   entityId,
            _entity_type: 'post',
            _sanitized:   true,
            _stored_at:   Date.now(),

            // Enrichment
            _images:     rendered.images || [],
            _links:      rendered.links || [],
            _summary:    this.sanitizer.extractPlainText(raw.body || '').slice(0, 500),
            _tags:       meta.tags || [],
            _word_count: rendered.wordCount || 0,
            _app:        typeof meta.app === 'string' ? meta.app : '',

            // Identity
            id:              VALIDATORS.safe_number(raw.id) ?? 0,
            author,
            permlink,
            category:        this.sanitizer.safeString(raw.category || '', 64),
            parent_author:   '',
            parent_permlink: this.sanitizer.safeString(raw.parent_permlink || '', 256),

            // Content — body IS sanitized HTML
            title: this.sanitizer.safeString(raw.title || '', 256),
            body:  rendered.html || '',

            // DANGEROUS field — keeps name, stores sanitized JSON string
            json_metadata: safeMetaStr,

            // Timestamps (integer ms)
            created:     VALIDATORS.safe_timestamp(raw.created),
            last_update: VALIDATORS.safe_timestamp(raw.last_update),
            active:      VALIDATORS.safe_timestamp(raw.active),
            cashout_time: VALIDATORS.safe_timestamp(raw.cashout_time),
            last_payout: VALIDATORS.safe_timestamp(raw.last_payout),

            // Hierarchy
            depth:    VALIDATORS.safe_number(raw.depth) ?? 0,
            children: VALIDATORS.safe_number(raw.children) ?? 0,

            // Voting
            net_votes:  VALIDATORS.safe_number(raw.net_votes) ?? 0,
            net_rshares: VALIDATORS.safe_numeric_string(raw.net_rshares) || '0',
            author_reputation: this.formatter ? this.formatter.reputation(raw.author_reputation) : 25,

            // Active votes — array of validated objects
            active_votes: Array.isArray(raw.active_votes)
                ? raw.active_votes
                    .map(v => VALIDATORS.safe_active_vote(v, this.sanitizer.sanitizeUsername.bind(this.sanitizer)))
                    .filter(Boolean)
                : [],

            // Payouts (translate chain symbols → display symbols)
            total_payout_value:         translateAssetFromChain(VALIDATORS.safe_asset(raw.total_payout_value) || '0.000 PXS'),
            curator_payout_value:       translateAssetFromChain(VALIDATORS.safe_asset(raw.curator_payout_value) || '0.000 PXS'),
            pending_payout_value:       translateAssetFromChain(VALIDATORS.safe_asset(raw.pending_payout_value) || '0.000 PXS'),
            total_pending_payout_value: translateAssetFromChain(VALIDATORS.safe_asset(raw.total_pending_payout_value) || '0.000 PXS'),
            max_accepted_payout:        translateAssetFromChain(VALIDATORS.safe_asset(raw.max_accepted_payout) || '1000000.000 PXS'),
            promoted:                   translateAssetFromChain(VALIDATORS.safe_asset(raw.promoted) || '0.000 PXS'),
            percent_pxs:                VALIDATORS.safe_percent(raw.percent_pxs) ?? 10000,
            author_rewards:             VALIDATORS.safe_number(raw.author_rewards) ?? 0,

            // Flags
            allow_replies:          VALIDATORS.safe_bool(raw.allow_replies) ?? true,
            allow_votes:            VALIDATORS.safe_bool(raw.allow_votes) ?? true,
            allow_curation_rewards: VALIDATORS.safe_bool(raw.allow_curation_rewards) ?? true,

            // Beneficiaries
            beneficiaries: Array.isArray(raw.beneficiaries)
                ? raw.beneficiaries.map(VALIDATORS.safe_beneficiary).filter(Boolean)
                : [],

            // Navigation / root
            url:           VALIDATORS.safe_url_path(raw.url) || `/@${author}/${permlink}`,
            root_title:    this.sanitizer.safeString(raw.root_title || '', 256),
            root_author:   raw.root_author ? (this.sanitizer.sanitizeUsername(raw.root_author) || '') : '',
            root_permlink: VALIDATORS.safe_permlink(raw.root_permlink) || '',
        };
    }

    // ── COMMENT ─────────────────────────────────────────────────────────

    /**
     * Sanitize a comment/reply (depth > 0) for storage.
     * Uses renderComment (stricter subset — no headings, tables, iframes).
     * Same field contract as sanitizePost (all dates = integer timestamps, etc.)
     *
     * @param {object} raw - Raw comment from blockchain RPC
     * @param {object} [renderOptions]
     * @returns {object|null} Sanitized comment ready for DB insertion
     */
    sanitizeComment(raw, renderOptions = {}) {
        if (!raw || !raw.author || !raw.permlink) return null;

        const author   = this.sanitizer.sanitizeUsername(raw.author);
        const permlink = VALIDATORS.safe_permlink(raw.permlink);
        if (!author || !permlink) return null;

        const entityId = `${author}_${permlink}`;

        // DANGEROUS: body
        const rendered = this.sanitizer.renderComment(raw.body || '', renderOptions);

        // DANGEROUS: json_metadata
        const safeMetaStr = this.sanitizer.safeJson(raw.json_metadata || '{}');
        let meta = {};
        try { meta = JSON.parse(safeMetaStr); } catch (e) {}

        return {
            _entity_id:   entityId,
            _entity_type: 'comment',
            _sanitized:   true,
            _stored_at:   Date.now(),

            // Enrichment
            _images:     rendered.images || [],
            _links:      rendered.links || [],
            _word_count: rendered.wordCount || 0,

            // Identity
            id:              VALIDATORS.safe_number(raw.id) ?? 0,
            author,
            permlink,
            parent_author:   raw.parent_author ? (this.sanitizer.sanitizeUsername(raw.parent_author) || '') : '',
            parent_permlink: VALIDATORS.safe_permlink(raw.parent_permlink) || '',

            // Content — body IS sanitized HTML
            title: '',
            body:  rendered.html || '',

            // DANGEROUS field — keeps name, stores sanitized JSON string
            json_metadata: safeMetaStr,

            // Timestamps (integer ms)
            created:      VALIDATORS.safe_timestamp(raw.created),
            last_update:  VALIDATORS.safe_timestamp(raw.last_update),
            active:       VALIDATORS.safe_timestamp(raw.active),
            cashout_time: VALIDATORS.safe_timestamp(raw.cashout_time),
            last_payout:  VALIDATORS.safe_timestamp(raw.last_payout),

            // Hierarchy
            depth:    VALIDATORS.safe_number(raw.depth) ?? 1,
            children: VALIDATORS.safe_number(raw.children) ?? 0,

            // Voting
            net_votes:  VALIDATORS.safe_number(raw.net_votes) ?? 0,
            net_rshares: VALIDATORS.safe_numeric_string(raw.net_rshares) || '0',
            author_reputation: this.formatter ? this.formatter.reputation(raw.author_reputation) : 25,

            active_votes: Array.isArray(raw.active_votes)
                ? raw.active_votes
                    .map(v => VALIDATORS.safe_active_vote(v, this.sanitizer.sanitizeUsername.bind(this.sanitizer)))
                    .filter(Boolean)
                : [],

            // Payouts (translate chain symbols → display symbols)
            pending_payout_value:       translateAssetFromChain(VALIDATORS.safe_asset(raw.pending_payout_value) || '0.000 PXS'),
            total_payout_value:         translateAssetFromChain(VALIDATORS.safe_asset(raw.total_payout_value) || '0.000 PXS'),
            curator_payout_value:       translateAssetFromChain(VALIDATORS.safe_asset(raw.curator_payout_value) || '0.000 PXS'),
            total_pending_payout_value: translateAssetFromChain(VALIDATORS.safe_asset(raw.total_pending_payout_value) || '0.000 PXS'),
            promoted:                   translateAssetFromChain(VALIDATORS.safe_asset(raw.promoted) || '0.000 PXS'),
            author_rewards:             VALIDATORS.safe_number(raw.author_rewards) ?? 0,

            // Flags
            allow_replies:          VALIDATORS.safe_bool(raw.allow_replies) ?? true,
            allow_votes:            VALIDATORS.safe_bool(raw.allow_votes) ?? true,
            allow_curation_rewards: VALIDATORS.safe_bool(raw.allow_curation_rewards) ?? true,

            // Navigation / root
            url:           VALIDATORS.safe_url_path(raw.url) || `/@${author}/${permlink}`,
            root_title:    this.sanitizer.safeString(raw.root_title || '', 256),
            root_author:   raw.root_author ? (this.sanitizer.sanitizeUsername(raw.root_author) || '') : '',
            root_permlink: VALIDATORS.safe_permlink(raw.root_permlink) || '',
        };
    }

    // ── AUTO-DETECT ─────────────────────────────────────────────────────

    /**
     * Auto-detect entity type and sanitize accordingly.
     * @param {object} raw - Raw content from blockchain
     * @param {object} [renderOptions]
     * @returns {object|null}
     */
    sanitizeContent(raw, renderOptions = {}) {
        if (!raw) return null;
        const isPost = (!raw.parent_author || raw.parent_author === '') && (raw.depth === 0 || raw.depth === undefined);
        return isPost
            ? this.sanitizePost(raw, renderOptions)
            : this.sanitizeComment(raw, renderOptions);
    }
}

/**
 * EntityStoreManager - Manages typed entity stores (accounts, posts, comments).
 * Each store is a LacertaDB collection where documents are indexed by _entity_id.
 * Provides get/upsert/resolve (batch) operations.
 */
class EntityStoreManager {
    /**
     * @param {object} db - LacertaDB database instance (pixa_cache)
     * @param {SanitizationPipeline} pipeline
     * @param {object} ttlConfig - ENTITY_TTL config
     */
    constructor(db, pipeline, ttlConfig) {
        this.db = db;
        this.pipeline = pipeline;
        this.ttl = ttlConfig;
        /** @type {Map<string, object>} collection name → LacertaDB collection */
        this.stores = new Map();
    }

    /**
     * Get or lazily create a collection for an entity type.
     * @param {'accounts'|'posts'|'comments'} type
     * @returns {Promise<object>}
     */
    async _store(type) {
        const name = `${type}_store`;
        if (!this.stores.has(name)) {
            try { await this.db.createCollection(name); } catch (e) {}
            this.stores.set(name, await this.db.getCollection(name));
        }
        return this.stores.get(name);
    }

    /**
     * Get a single entity by ID from its typed store.
     * Returns null if missing or stale (past TTL).
     * @param {'accounts'|'posts'|'comments'} type
     * @param {string} entityId
     * @returns {Promise<object|null>}
     */
    async get(type, entityId) {
        try {
            const store = await this._store(type);
            const doc = await store.get(entityId);
            if (!doc) return null;

            const ttl = this.ttl[type] || 60000;
            if (doc._stored_at && (Date.now() - doc._stored_at) < ttl) {
                return doc;
            }
            // Stale — treat as miss
            return null;
        } catch (e) {
            return null;
        }
    }

    /**
     * Upsert a single sanitized entity into its typed store.
     * The entity MUST already be sanitized (has _entity_id).
     * @param {'accounts'|'posts'|'comments'} type
     * @param {object} sanitizedEntity
     */
    async upsert(type, sanitizedEntity) {
        if (!sanitizedEntity || !sanitizedEntity._entity_id) return;
        if (!sanitizedEntity._sanitized) {
            console.warn(`[EntityStoreManager] Rejected unsanitized entity for ${type}`);
            return;
        }
        try {
            const store = await this._store(type);
            const id = sanitizedEntity._entity_id;
            try {
                await store.add(sanitizedEntity, { id });
            } catch (e) {
                await store.update(id, sanitizedEntity);
            }
        } catch (e) {
            console.warn(`[EntityStoreManager] upsert(${type}) error:`, e.message);
        }
    }

    /**
     * Upsert multiple sanitized entities in batch.
     * @param {'accounts'|'posts'|'comments'} type
     * @param {object[]} entities - Array of sanitized entities
     */
    async upsertMany(type, entities) {
        for (const entity of entities) {
            await this.upsert(type, entity);
        }
    }

    /**
     * Resolve a list of entity IDs from a typed store.
     * Returns entities in the same order as the IDs. Missing/stale entries are null.
     * @param {'accounts'|'posts'|'comments'} type
     * @param {string[]} ids
     * @returns {Promise<(object|null)[]>}
     */
    async resolve(type, ids) {
        const results = [];
        for (const id of ids) {
            results.push(await this.get(type, id));
        }
        return results;
    }

    /**
     * Invalidate a single entity.
     * @param {'accounts'|'posts'|'comments'} type
     * @param {string} entityId
     */
    async invalidate(type, entityId) {
        try {
            const store = await this._store(type);
            await store.delete(entityId);
        } catch (e) {}
    }

    /**
     * Invalidate all entities in a store.
     * @param {'accounts'|'posts'|'comments'} type
     */
    async invalidateAll(type) {
        try {
            const store = await this._store(type);
            const docs = await store.find({});
            for (const doc of docs) {
                try { await store.delete(doc._id || doc.id || doc._entity_id); } catch (e) {}
            }
        } catch (e) {}
    }
}

/**
 * QueryCacheManager - Caches query results as arrays of entity IDs.
 * Each cached query stores { ids: string[], entity_type: string, timestamp: number }.
 * On cache hit (within TTL), IDs are resolved from EntityStoreManager.
 * On cache miss/stale, the caller must re-fetch and call store().
 */
class QueryCacheManager {
    /**
     * @param {object} db - LacertaDB database instance (pixa_cache)
     * @param {object} ttlConfig - QUERY_TTL config
     */
    constructor(db, ttlConfig) {
        this.db = db;
        this.ttl = ttlConfig;
        this._collection = null;
    }

    /** @returns {Promise<object>} LacertaDB collection */
    async _col() {
        if (!this._collection) {
            try { await this.db.createCollection('query_cache'); } catch (e) {}
            this._collection = await this.db.getCollection('query_cache');
        }
        return this._collection;
    }

    /**
     * Build a deterministic cache key from query descriptor.
     * @param {string} namespace - e.g. 'trending', 'blog', 'content', 'accounts'
     * @param {object} params - Query parameters
     * @returns {string}
     */
    static buildKey(namespace, params = {}) {
        const parts = [namespace];
        const sortedKeys = Object.keys(params).sort();
        for (const k of sortedKeys) {
            const v = params[k];
            if (v !== undefined && v !== null && v !== '') {
                parts.push(`${k}=${v}`);
            }
        }
        return parts.join(':');
    }

    /**
     * Look up cached query result (array of entity IDs).
     * Returns null if not cached or stale.
     * @param {string} queryKey
     * @param {string} [ttlCategory] - Key into QUERY_TTL config (e.g. 'trending')
     * @returns {Promise<{ids: string[], entity_type: string}|null>}
     */
    async get(queryKey, ttlCategory) {
        try {
            const col = await this._col();
            const doc = await col.get(queryKey);
            if (!doc) return null;

            const ttl = (ttlCategory && this.ttl[ttlCategory]) || 60000;
            if (doc.timestamp && (Date.now() - doc.timestamp) < ttl) {
                return { ids: doc.ids || [], entity_type: doc.entity_type || 'posts' };
            }
            return null;
        } catch (e) {
            return null;
        }
    }

    /**
     * Store a query result (as an array of entity IDs).
     * @param {string} queryKey
     * @param {string[]} ids - Entity IDs in result order
     * @param {string} entityType - 'accounts'|'posts'|'comments'
     */
    async store(queryKey, ids, entityType = 'posts') {
        try {
            const col = await this._col();
            const doc = { ids, entity_type: entityType, timestamp: Date.now() };
            try { await col.add(doc, { id: queryKey }); }
            catch (e) { await col.update(queryKey, doc); }
        } catch (e) {
            console.warn('[QueryCacheManager] store error:', e.message);
        }
    }

    /**
     * Invalidate a specific query.
     * @param {string} queryKey
     */
    async invalidate(queryKey) {
        try {
            const col = await this._col();
            await col.delete(queryKey);
        } catch (e) {}
    }

    /**
     * Invalidate all queries matching a prefix/namespace.
     * @param {string} prefix
     */
    async invalidateByPrefix(prefix) {
        try {
            const col = await this._col();
            const docs = await col.find({});
            for (const doc of docs) {
                const key = doc._id || doc.id;
                if (key && key.startsWith(prefix)) {
                    try { await col.delete(key); } catch (e) {}
                }
            }
        } catch (e) {}
    }
}

class ContentSanitizer {
    constructor() {
        this.ready = false;
        this._initPromise = null;

        /** @type {object} Default sanitize options (v0.2 SanitizeOptions) */
        this.defaultOptions = {
            internal_domains: ['pixa.pics'],
            max_body_length: 500000,
            max_image_count: 0,
        };
    }

    /**
     * Initialize the pixa-content WASM module
     * @param {string|URL} [wasmPath] - Optional path/URL to the .wasm file
     * @returns {Promise<void>}
     */
    async initialize(wasmPath) {
        if (this.ready) return;
        if (this._initPromise) return this._initPromise;

        this._initPromise = (async () => {
            try {
                // pixaContentInit is the default export — call it to boot the WASM
                if (wasmPath) {
                    await pixaContentInit(wasmPath);
                } else {
                    await pixaContentInit();
                }
                this.ready = true;
                console.log('[ContentSanitizer] pixa-content WASM engine initialized');
            } catch (e) {
                console.error('[ContentSanitizer] Failed to initialize pixa-content:', e);
                this.ready = false;
                throw e;
            }
        })();

        return this._initPromise;
    }

    /**
     * Update default internal domains (e.g. when config changes)
     * @param {string[]} domains
     */
    setInternalDomains(domains) {
        if (Array.isArray(domains)) {
            this.defaultOptions.internal_domains = domains;
        }
    }

    /**
     * SECURITY PATCH (v3.5.2-patched): Fail-closed guard.
     * Throws instead of silently returning fallback values when WASM is not ready.
     * @param {string} methodName - Caller method name for error context
     * @throws {PixaAPIError} if WASM engine is not initialized
     */
    _requireReady(methodName) {
        if (!this.ready) {
            throw new PixaAPIError(
                `ContentSanitizer.${methodName}(): WASM engine not initialized — cannot sanitize safely`,
                'SANITIZER_NOT_READY'
            );
        }
    }

    /**
     * Render a post body through pixa-content WASM sanitizer
     * Returns sanitized HTML, extracted images, extracted links, and word count.
     *
     * @param {string} body - Raw post body (Markdown or HTML)
     * @param {object} [options] - Override render options
     * @returns {{ html: string, images: Array, links: Array, wordCount: number }}
     */
    renderPost(body, options = {}) {
        if (!body) return { html: '', images: [], links: [], wordCount: 0 };
        this._requireReady('renderPost');

        // SECURITY PATCH: No try/catch fallback — WASM errors must propagate
        const opts = { ...this.defaultOptions, ...options };
        const result = wasmSanitizePost(body, JSON.stringify(opts));

        return {
            html: result.html || '',
            images: result.images || [],
            links: result.links || [],
            wordCount: this._countWords(result.html || body),
        };
    }

    /**
     * Render a comment body (stricter subset — no headings, tables, iframes)
     *
     * @param {string} body - Raw comment body
     * @param {object} [options] - Override render options
     * @returns {{ html: string, images: Array, links: Array, wordCount: number }}
     */
    renderComment(body, options = {}) {
        if (!body) return { html: '', images: [], links: [], wordCount: 0 };
        this._requireReady('renderComment');

        const opts = { ...this.defaultOptions, ...options };
        const result = wasmSanitizeComment(body, JSON.stringify(opts));

        return {
            html: result.html || '',
            images: [],
            links: result.links || [],
            wordCount: this._countWords(result.html || body),
        };
    }

    /**
     * Render a memo (bold, italic, @mentions, #hashtags only)
     * v0.2: New tier.
     * @param {string} body
     * @param {object} [options]
     * @returns {{ html: string }}
     */
    renderMemo(body, options = {}) {
        if (!body) return { html: '' };
        this._requireReady('renderMemo');

        const opts = { ...this.defaultOptions, ...options };
        return wasmSanitizeMemo(body, JSON.stringify(opts));
    }

    /**
     * Sanitize a JSON string — all keys validated, strings stripped.
     * Input: JSON string. Output: sanitized JSON string.
     * v0.2: New primitive.
     * @param {string} jsonStr
     * @returns {string} Sanitized JSON string
     */
    safeJson(jsonStr) {
        if (!jsonStr) return '{}';
        this._requireReady('safeJson');
        return wasmSafeJson(jsonStr);
    }

    /**
     * Sanitize a single string value — strips HTML, rejects embedded JSON.
     * v0.2: New primitive.
     * @param {string} s
     * @param {number} [maxLen=10000]
     * @returns {string}
     */
    safeString(s, maxLen = 10000) {
        if (!s || typeof s !== 'string') return '';
        this._requireReady('safeString');
        return wasmSafeString(s, maxLen) || '';
    }

    /**
     * Extract clean plain text from body (strip all formatting)
     * @param {string} body
     * @returns {string}
     */
    extractPlainText(body) {
        if (!body) return '';
        this._requireReady('extractPlainText');
        return wasmExtractPlainText(body);
    }

    /**
     * TF-IDF extractive summarization
     * @param {string} body
     * @param {number} [sentenceCount=3]
     * @returns {{ summary: string, keywords: Array, sentences: Array }}
     */
    summarize(body, sentenceCount = 3) {
        if (!body) return { summary: '', keywords: [], sentences: [] };
        this._requireReady('summarize');
        return wasmSummarizeContent(body, sentenceCount);
    }

    /**
     * Validate and sanitize username (HIVE-compatible: 3-16 chars, a-z0-9.-)
     * @param {string} rawUsername
     * @returns {string} Sanitized username or '' if invalid
     */
    sanitizeUsername(rawUsername) {
        if (!rawUsername) return '';
        this._requireReady('sanitizeUsername');
        return wasmSanitizeUsername(rawUsername);
    }

    /**
     * Legacy compatibility: processBlogPost wraps renderPost
     * @param {string} body
     * @param {object} [options]
     * @returns {{ body: string, _images: Array, _links: Array, _word_count: number }}
     */
    processBlogPost(body, options = {}) {
        const result = this.renderPost(body, options);
        return {
            body: result.html,
            _images: result.images,
            _links: result.links,
            _word_count: result.wordCount,
        };
    }

    /**
     * Fallback processing when WASM is not available
     * @private
     */
    /**
     * Word count helper
     * @private
     */
    _countWords(text) {
        const plain = text.replace(/<[^>]*>/g, '');
        return plain.split(/\s+/).filter(w => w.length > 0).length;
    }
}

class KeyManager {
    constructor(emitter, config) {
        this.emitter = emitter;
        this.config = config;
        this.sessionKeys = new Map();
        /** @type {number} Failed PIN attempt counter */
        this._pinAttempts = 0;
        /** @type {number} Timestamp of lockout start (0 = not locked) */
        this._pinLockoutUntil = 0;
        /** @type {Promise|null} Active PIN unlock promise (prevents double-dialog) */
        this._pendingPinUnlock = null;
        this.unencrypted = null;
        this.vaultDbReference = null;
        this.vaultMaster = null;
        this.vaultIndividual = null;
        this.activeAccount = null;
        this.pinVerified = false;
        this.pinVerificationTime = 0;
        /** @private AES-GCM CryptoKey for in-memory key encryption (non-extractable, memory-only) */
        this._sessionCryptoKey = null;
        /** @private Bound cleanup handler for tab-close events */
        this._cleanupBound = null;
        /** @private Reference to the proxy's unlockWithPin for PIN re-verification */
        this._unlockWithPin = null;
    }

    setPinTimeout(timeout) {
        if (this.config) { this.config.PIN_TIMEOUT = timeout; }
    }

    /**
     * Reset the PIN verification timer. Called from all paths that verify
     * the PIN or accept a raw key — ensures keys stay in-memory for the
     * full PIN_TIMEOUT duration from this moment.
     */
    resetPinTimer() {
        this.pinVerified = true;
        this.pinVerificationTime = Date.now();
    }

    /**
     * Migrate keys currently in sessionKeys (in-memory) and/or in the
     * unencrypted collection into the encrypted vault.  Called after vault
     * creation to ensure keys from a prior quickLogin are persisted.
     * @param {string} account - normalized account name
     */
    async migrateKeysToVault(account) {
        const normalizedAccount = normalizeAccount(account);
        if (!normalizedAccount) return;

        const types = ['posting', 'active', 'owner', 'memo'];
        // Track which individual keys have already been written to vault
        // to avoid double-writes (section 1 from unencrypted, section 2 from sessionKeys).
        // LacertaDB's encrypted vault `update` path can fail with TurboSerial
        // deserialization errors, so we use add-only and silently skip conflicts.
        const writtenKeys = new Set();

        // 1. Try to migrate from unencrypted DB → vault
        if (this.unencrypted) {
            // Master keys (all 4 derived from master password)
            try {
                const masterDoc = await this.unencrypted.get(normalizedAccount);
                if (masterDoc && masterDoc.derived_keys) {
                    if (this.vaultMaster) {
                        try {
                            await this.vaultMaster.add(
                                { account: normalizedAccount, derived_keys: masterDoc.derived_keys, created_at: Date.now() },
                                { id: normalizedAccount }
                            );
                            console.debug('[migrateKeysToVault] Keys migrated to vault');
                        } catch (e) {
                            // Already exists — skip (don't use update — it triggers TurboSerial errors)
                            console.debug('[migrateKeysToVault] Master keys already in vault');
                        }
                        // Mark all types as written (master key derives all 4)
                        types.forEach(t => writtenKeys.add(`${normalizedAccount}_${t}`));
                    }
                    // Also ensure they're in the in-memory cache
                    await this.cacheKeys(normalizedAccount, masterDoc.derived_keys);
                }
            } catch (e) { /* no master doc */ }

            // Individual keys
            for (const type of types) {
                const id = `${normalizedAccount}_${type}`;
                if (writtenKeys.has(id)) continue; // Already handled by master keys
                try {
                    const doc = await this.unencrypted.get(id);
                    if (doc && doc.key && this.vaultIndividual) {
                        try {
                            await this.vaultIndividual.add(
                                { account: normalizedAccount, type, key: doc.key, created_at: Date.now() },
                                { id }
                            );
                            console.debug(`[migrateKeysToVault] Keys migrated to vault`);
                        } catch (e) {
                            // Already exists — skip
                        }
                        writtenKeys.add(id);
                    }
                } catch (e) { /* no individual doc */ }
            }
        }

        // 2. Migrate from sessionKeys → vault (keys that were only in-memory)
        for (const type of types) {
            const cacheKey = `${normalizedAccount}_${type}`;
            if (writtenKeys.has(cacheKey)) continue; // Already migrated above

            const entry = this.sessionKeys.get(cacheKey);
            if (!entry) continue;

            const plainKey = await this._decryptFromCache(entry);
            if (!plainKey) continue;

            if (this.vaultIndividual) {
                try {
                    await this.vaultIndividual.add(
                        { account: normalizedAccount, type, key: plainKey, created_at: Date.now() },
                        { id: cacheKey }
                    );
                    console.debug(`[migrateKeysToVault] Keys migrated to vault`);
                } catch (e) {
                    // Already exists — skip (add-only, no update)
                }
            }
        }

        // SECURITY FIX (v3.5.2): After successful migration, delete plaintext
        // keys from the unencrypted collection. They are now safely in the vault.
        if (this.unencrypted) {
            try {
                await this.unencrypted.delete(normalizedAccount);
            } catch (e) { /* may not exist */ }
            for (const type of types) {
                try {
                    await this.unencrypted.delete(`${normalizedAccount}_${type}`);
                } catch (e) { /* may not exist */ }
            }
        }
    }

    /**
     * Generate a random AES-GCM CryptoKey for encrypting session keys in memory.
     * The key is non-extractable and lives only in JS heap — it cannot be
     * serialized, persisted, or read from devtools. When the tab closes or the
     * PIN expires, it is destroyed and the encrypted blobs become unrecoverable.
     */
    /**
     * Record a failed PIN attempt and enforce lockout.
     * @returns {{ locked: boolean, remainingSec: number }}
     */
    _recordFailedPinAttempt() {
        this._pinAttempts++;
        const maxAttempts = this.config.PIN_MAX_ATTEMPTS || 10;
        if (this._pinAttempts >= maxAttempts) {
            this._pinLockoutUntil = Date.now() + (this.config.PIN_LOCKOUT_MS || 300000);
            this._pinAttempts = 0; // Reset counter; lockout timer takes over
            return { locked: true, remainingSec: Math.ceil((this.config.PIN_LOCKOUT_MS || 300000) / 1000) };
        }
        return { locked: false, remainingSec: 0 };
    }

    async _generateSessionCryptoKey() {
        // Destroy any existing key first
        this._destroySessionCrypto(false);

        this._sessionCryptoKey = await crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            false, // non-extractable
            ['encrypt', 'decrypt']
        );

        // Register tab-close cleanup
        if (typeof globalThis !== 'undefined' && globalThis.addEventListener) {
            this._cleanupBound = () => this._destroySessionCrypto(true);
            globalThis.addEventListener('pagehide', this._cleanupBound);
            globalThis.addEventListener('beforeunload', this._cleanupBound);
        }
    }

    /**
     * Encrypt a plaintext key for in-memory storage.
     * Falls back to plaintext if no session CryptoKey (quickLogin path).
     * @param {string} plaintext - The private key string
     * @returns {Promise<object|string>} Encrypted blob {_enc, iv, ct} or plaintext
     */
    async _encryptForCache(plaintext) {
        if (!this._sessionCryptoKey) return plaintext;
        const encoder = new TextEncoder();
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ct = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            this._sessionCryptoKey,
            encoder.encode(plaintext)
        );
        return { _enc: true, iv, ct };
    }

    /**
     * Decrypt a cached key blob back to plaintext.
     * Returns plaintext strings as-is (quickLogin keys).
     * Returns null if CryptoKey has been destroyed (expired/tab closed).
     * @param {object|string} blob - Encrypted blob or plaintext string
     * @returns {Promise<string|null>} Decrypted key or null
     */
    async _decryptFromCache(blob) {
        if (!blob) return null;
        if (typeof blob === 'string') return blob; // plaintext (quickLogin)
        if (!blob._enc) return null;
        if (!this._sessionCryptoKey) return null; // CryptoKey destroyed
        try {
            const plaintext = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: blob.iv },
                this._sessionCryptoKey,
                blob.ct
            );
            return new TextDecoder().decode(plaintext);
        } catch (e) {
            return null; // decryption failed — key was likely destroyed
        }
    }

    /**
     * Destroy the session CryptoKey and wipe all encrypted cached keys.
     * Called on PIN expiry, tab close, and explicit lock.
     * @param {boolean} clearKeys - Whether to also clear the sessionKeys Map
     */
    _destroySessionCrypto(clearKeys = true) {
        this._sessionCryptoKey = null;
        if (clearKeys) {
            this.sessionKeys.clear();
            this.pinVerified = false;
            this.pinVerificationTime = 0;
        }
        if (this._cleanupBound && typeof globalThis !== 'undefined' && globalThis.removeEventListener) {
            globalThis.removeEventListener('pagehide', this._cleanupBound);
            globalThis.removeEventListener('beforeunload', this._cleanupBound);
            this._cleanupBound = null;
        }
    }

    async setDependencies(settingsDb) {
        try { await settingsDb.createCollection('unencrypted_keys'); } catch(e) {}
        try { this.unencrypted = await settingsDb.getCollection('unencrypted_keys'); } catch(e) {}
    }

    async setVault(vaultDb) {
        this.vaultDbReference = vaultDb;
        if (vaultDb) {
            try { await vaultDb.createCollection('master_keys'); } catch(e){}
            try { await vaultDb.createCollection('individual_keys'); } catch(e){}
            this.vaultMaster = await vaultDb.getCollection('master_keys');
            this.vaultIndividual = await vaultDb.getCollection('individual_keys');
        }
    }

    async unlockVault(pin) {
        try {
            await this._generateSessionCryptoKey();
            this.resetPinTimer();
            try { await this.vaultDbReference.createCollection('master_keys'); } catch(e){}
            try { await this.vaultDbReference.createCollection('individual_keys'); } catch(e){}
            this.vaultMaster = await this.vaultDbReference.getCollection('master_keys');
            this.vaultIndividual = await this.vaultDbReference.getCollection('individual_keys');
            return true;
        } catch (e) {
            this.pinVerified = false;
            this.pinVerificationTime = 0;
            throw new Error("Invalid PIN or Vault Error");
        }
    }

    async lock() {
        this._destroySessionCrypto(true);
        this.vaultMaster = null;
        this.vaultIndividual = null;
    }

    isPINValid() {
        if (!this.pinVerified || this.pinVerificationTime <= 0) return false;
        const timeout = this.config.PIN_TIMEOUT || 15 * 60 * 1000;
        if ((Date.now() - this.pinVerificationTime) >= timeout) {
            // PIN expired — destroy CryptoKey and wipe all cached keys
            this._destroySessionCrypto(true);
            return false;
        }
        return true;
    }

    async cacheKeys(account, keys) {
        const normalizedAccount = normalizeAccount(account);
        if (!normalizedAccount) return;
        for (const [type, key] of Object.entries(keys)) {
            const stored = await this._encryptForCache(key);
            this.sessionKeys.set(`${normalizedAccount}_${type}`, stored);
        }
    }

    async requestKey(account, type) {
        const normalizedAccount = normalizeAccount(account);
        if (!normalizedAccount) throw new KeyNotFoundError(account, type);

        const sessionEntry = this.sessionKeys.get(`${normalizedAccount}_${type}`);
        if (sessionEntry) {
            // If PIN was used but has expired, destroy crypto and deny
            if (this.pinVerificationTime > 0 && !this.isPINValid()) {
                // isPINValid() auto-destroys; fall through to vault/PIN check
            } else {
                const decrypted = await this._decryptFromCache(sessionEntry);
                if (decrypted) return decrypted;
                // Decryption failed (CryptoKey gone) — clear stale entry
                this.sessionKeys.delete(`${normalizedAccount}_${type}`);
            }
        }

        if (this.vaultMaster && this.isPINValid()) {
            try {
                const master = await this.vaultMaster.get(normalizedAccount);
                if (master && master.derived_keys && master.derived_keys[type]) {
                    await this.cacheKeys(normalizedAccount, master.derived_keys);
                    return master.derived_keys[type];
                }
            } catch (e) {}
        }

        if (this.vaultIndividual && this.isPINValid()) {
            try {
                const indKey = await this.vaultIndividual.get(`${normalizedAccount}_${type}`);
                if (indKey && indKey.key) {
                    const stored = await this._encryptForCache(indKey.key);
                    this.sessionKeys.set(`${normalizedAccount}_${type}`, stored);
                    return indKey.key;
                }
            } catch (e) {}
        }

        // If vault is configured but PIN has expired, request PIN unlock
        // instead of asking for the raw private key
        if (this.vaultDbReference && !this.isPINValid()) {
            // SECURITY FIX (v3.5.2): Queue concurrent PIN requests to prevent
            // double-dialog. If a PIN prompt is already active, wait for it.
            if (this._pendingPinUnlock) {
                try {
                    await this._pendingPinUnlock;
                    // PIN was unlocked by the other request — retry key fetch
                    const cachedEntry = this.sessionKeys.get(`${normalizedAccount}_${type}`);
                    if (cachedEntry) {
                        const decrypted = await this._decryptFromCache(cachedEntry);
                        if (decrypted) return decrypted;
                    }
                } catch (e) {
                    // Previous unlock failed — fall through to show our own dialog
                }
            }

            const pinPromise = new Promise((resolve, reject) => {
                const timeout = setTimeout(() => {
                    reject(new KeyNotFoundError(normalizedAccount, type));
                }, 120000); // 2 minutes to allow retries

                const emitData = {
                    account: normalizedAccount,
                    type,
                    reason: `PIN required for ${type} operation`,
                    callback: null, // pinCallback — set below
                    keyCallback: null // keyCallback — set below (Enter Key path)
                };

                // PIN callback: UI provides the PIN, we verify + unlock + retry key fetch.
                // On wrong PIN: throws so UI shows "Incorrect PIN"; dialog stays open for retry.
                // On correct PIN: resolves the outer Promise with the decrypted key.
                // On hard failure: rejects the outer Promise.
                const pinCallback = async (pin) => {
                    if (!this._unlockWithPin) {
                        clearTimeout(timeout);
                        reject(new Error('PIN unlock not available'));
                        return;
                    }

                    const unlockResult = await this._unlockWithPin(pin, {
                        account: normalizedAccount,
                        keyType: type
                    });

                    if (!unlockResult.success) {
                        // Wrong PIN — throw so the UI handler's catch shows "Incorrect PIN"
                        // snackbar. The dialog stays open and the user can retry.
                        throw new Error(unlockResult.error || 'Incorrect PIN');
                    }

                    // PIN verified and keys loaded — clear the timeout
                    clearTimeout(timeout);

                    // Read the key from cache (unlockWithPin should have loaded it)
                    const cachedEntry = this.sessionKeys.get(`${normalizedAccount}_${type}`);
                    if (cachedEntry) {
                        const decrypted = await this._decryptFromCache(cachedEntry);
                        if (decrypted) {
                            resolve(decrypted);
                            return;
                        }
                    }

                    // Fallback: try vault read directly
                    if (this.vaultMaster && this.isPINValid()) {
                        try {
                            const master = await this.vaultMaster.get(normalizedAccount);
                            if (master && master.derived_keys && master.derived_keys[type]) {
                                await this.cacheKeys(normalizedAccount, master.derived_keys);
                                resolve(master.derived_keys[type]);
                                return;
                            }
                        } catch (e) {}
                    }

                    if (this.vaultIndividual && this.isPINValid()) {
                        try {
                            const indKey = await this.vaultIndividual.get(`${normalizedAccount}_${type}`);
                            if (indKey && indKey.key) {
                                const stored = await this._encryptForCache(indKey.key);
                                this.sessionKeys.set(`${normalizedAccount}_${type}`, stored);
                                resolve(indKey.key);
                                return;
                            }
                        } catch (e) {}
                    }

                    // PIN was correct but key not found — hard failure
                    reject(new KeyNotFoundError(normalizedAccount, type));
                };

                // Key callback: UI provides a raw private key directly.
                // UnlockKeyDialog already validates, caches (encrypted), and
                // resets the PIN timer before invoking this callback.
                // We just need to resolve the pending requestKey Promise.
                const keyCallback = async (key) => {
                    clearTimeout(timeout);
                    // Ensure session crypto + PIN state is set (defense in depth)
                    if (!this._sessionCryptoKey) {
                        await this._generateSessionCryptoKey();
                    }
                    this.resetPinTimer();
                    resolve(key);
                };

                emitData.callback = pinCallback;
                emitData.keyCallback = keyCallback;
                this.emitter.emit('pin_required', emitData);
            });

            this._pendingPinUnlock = pinPromise;
            pinPromise.finally(() => { this._pendingPinUnlock = null; });
            return pinPromise;
        }

        return new Promise((resolve, reject) => {
            const eventName = `key_request_${normalizedAccount}_${type}`;
            const timeout = setTimeout(() => {
                this.emitter.removeListener(eventName, keyResponseHandler);
                reject(new KeyNotFoundError(normalizedAccount, type));
            }, 60000);

            // Create a callback that UI can use to provide the key
            const callback = async (key, shouldStore = false, isMaster = false) => {
                clearTimeout(timeout);
                try {
                    if (isMaster) {
                        const derivedKeys = await this.addAccountWithMasterKey(normalizedAccount, key, { storeInVault: shouldStore });
                        resolve(derivedKeys[type]);
                    } else {
                        await this.addIndividualKey(normalizedAccount, type, key, { storeInVault: shouldStore });
                        resolve(key);
                    }
                } catch (e) {
                    reject(e);
                }
            };

            this.emitter.emit('key_required', { account: normalizedAccount, type, callback });

            // Also listen for the legacy event-based response
            const keyResponseHandler = async (keyInput) => {
                clearTimeout(timeout);
                try {
                    if (typeof keyInput === 'object' && keyInput.masterPassword) {
                        const derivedKeys = await this.addAccountWithMasterKey(normalizedAccount, keyInput.masterPassword, { storeInVault: keyInput.save });
                        resolve(derivedKeys[type]);
                    } else {
                        const keyValue = typeof keyInput === 'object' ? keyInput.key : keyInput;
                        const shouldSave = typeof keyInput === 'object' ? keyInput.save : false;
                        await this.addIndividualKey(normalizedAccount, type, keyValue, { storeInVault: shouldSave });
                        resolve(keyValue);
                    }
                } catch(e) { reject(e); }
            };
            this.emitter.once(eventName, keyResponseHandler);
        });
    }

    async addAccountWithMasterKey(account, masterPassword, options = {}) {
        const normalizedAccount = normalizeAccount(account);
        if (!normalizedAccount) throw new Error('Invalid account');

        const derivedKeys = {
            posting: PrivateKey.fromLogin(normalizedAccount, masterPassword, 'posting').toString(),
            active: PrivateKey.fromLogin(normalizedAccount, masterPassword, 'active').toString(),
            owner: PrivateKey.fromLogin(normalizedAccount, masterPassword, 'owner').toString(),
            memo: PrivateKey.fromLogin(normalizedAccount, masterPassword, 'memo').toString()
        };

        await this.cacheKeys(normalizedAccount, derivedKeys);

        // SECURITY FIX (v3.5.2): Never store keys in the unencrypted collection
        // when a vault is active. Plaintext IndexedDB storage is accessible to
        // any same-origin script (XSS), browser extension, or physical attacker.
        if (this.vaultMaster) {
            // Store ONLY in encrypted vault
            try {
                await this.vaultMaster.add(
                    { account: normalizedAccount, derived_keys: derivedKeys, created_at: Date.now() },
                    { id: normalizedAccount }
                );
            } catch (e) {
                // Already exists — skip (don't use update — encrypted vault update can fail)
            }
        } else if (this.unencrypted) {
            // No vault available (quickLogin before vault setup) — store in
            // unencrypted as temporary fallback. These MUST be migrated to the
            // vault and deleted from unencrypted on next initializeVault().
            // SECURITY: Exclude owner key from unencrypted storage — owner key
            // can change all other keys and steal the account entirely.
            const safeKeys = { posting: derivedKeys.posting, active: derivedKeys.active, memo: derivedKeys.memo };
            try {
                await this.unencrypted.add(
                    { account: normalizedAccount, derived_keys: safeKeys, created_at: Date.now() },
                    { id: normalizedAccount }
                );
            } catch (e) {
                try {
                    await this.unencrypted.update(normalizedAccount, { derived_keys: safeKeys, updated_at: Date.now() });
                } catch (e2) { /* ignore */ }
            }
        }

        return derivedKeys;
    }

    async addIndividualKey(account, type, key, options = {}) {
        const normalizedAccount = normalizeAccount(account);
        if (!normalizedAccount) throw new Error('Invalid account');

        const stored = await this._encryptForCache(key);
        this.sessionKeys.set(`${normalizedAccount}_${type}`, stored);

        // SECURITY FIX (v3.5.2): Vault-first storage. Never store in unencrypted
        // when vault is available. Never store owner keys in unencrypted at all.
        if (this.vaultIndividual) {
            const id = `${normalizedAccount}_${type}`;
            try {
                await this.vaultIndividual.add(
                    { account: normalizedAccount, type, key, created_at: Date.now() },
                    { id }
                );
            } catch (e) {
                // Already exists — skip
            }
        } else if (this.unencrypted && type !== 'owner') {
            // Temporary unencrypted fallback (no vault yet). Exclude owner keys.
            const id = `${normalizedAccount}_${type}`;
            try {
                await this.unencrypted.add({ account: normalizedAccount, type, key, created_at: Date.now() }, { id });
            } catch (e) {
                try { await this.unencrypted.update(id, { key, updated_at: Date.now() }); } catch (e2) { /* ignore */ }
            }
        }
    }

    async loadUnencryptedKeys(account) {
        if (!this.unencrypted) return false;
        const normalizedAccount = normalizeAccount(account);
        if (!normalizedAccount) return false;

        let foundAny = false;
        try {
            const data = await this.unencrypted.get(normalizedAccount);
            if (data && data.derived_keys) {
                await this.cacheKeys(normalizedAccount, data.derived_keys);
                foundAny = true;
            }
        } catch(e) {}

        const types = ['posting', 'active', 'owner', 'memo'];
        for (const type of types) {
            try {
                const id = `${normalizedAccount}_${type}`;
                const data = await this.unencrypted.get(id);
                if (data && data.key) {
                    const stored = await this._encryptForCache(data.key);
                    this.sessionKeys.set(id, stored);
                    foundAny = true;
                }
            } catch(e) {}
        }
        return foundAny;
    }

    async clearAllSessions(clearStorage = false) {
        this._destroySessionCrypto(true);
        this.activeAccount = null;
        this.vaultMaster = null;
        this.vaultIndividual = null;

        if (clearStorage && this.unencrypted) {
            try {
                const allDocs = await this.unencrypted.find({});
                if (allDocs && allDocs.length) {
                    for (const doc of allDocs) {
                        try { await this.unencrypted.delete(doc._id || doc.id || doc.account); } catch (e) {}
                    }
                }
            } catch (e) {}
        }
    }

    hasKey(account, type) {
        const normalizedAccount = normalizeAccount(account);
        if (!normalizedAccount) return false;
        // Trigger auto-cleanup if PIN expired (isPINValid auto-destroys)
        if (this.pinVerificationTime > 0 && !this.isPINValid()) {
            return false;
        }
        return this.sessionKeys.has(`${normalizedAccount}_${type}`);
    }

    /**
     * @removed v3.5.2 — Returned plaintext keys for quickLogin sessions.
     * Use requestKey() (async) which properly decrypts in-memory encrypted keys.
     */
    getKeySync(_account, _type) {
        return null;
    }

    setActiveAccount(acc) {
        this.activeAccount = normalizeAccount(acc);
    }

    getActiveAccount() {
        return this.activeAccount;
    }
}

class SessionManager {
    constructor(db, config) {
        this.config = config;
        this.db = db;
        this.sessions = null;
        this.preferences = null;
        this.currentAccount = null;
        this.eventEmitter = null;
    }

    setSessionTimeout(timeout) {
        if (this.config) { this.config.SESSION_TIMEOUT = timeout; }
    }

    async initialize(eventEmitter) {
        this.eventEmitter = eventEmitter;
        try { await this.db.createCollection('sessions'); } catch(e){}
        try { await this.db.createCollection('preferences'); } catch(e){}
        this.sessions = await this.db.getCollection('sessions');
        this.preferences = await this.db.getCollection('preferences');
    }

    /**
     * Get the currently active account (with expiration check)
     * @returns {Promise<string|null>}
     */
    async getActiveAccount() {
        try {
            if (!this.preferences || !this.sessions) return null;

            let pref;
            try { pref = await this.preferences.get('active_account'); } catch (_) { return null; }
            if (!pref || !pref.account) return null;

            const account = pref.account;

            let sessionData;
            try { sessionData = await this.sessions.get(account); } catch (_) { sessionData = null; }

            if (!sessionData) {
                // Session record missing - clear stale preference
                try { await this.preferences.delete('active_account'); } catch (e) {}
                return null;
            }

            // Check expiration
            if (Date.now() > sessionData.expires_at) {
                await this.clearSession();
                this.eventEmitter?.emit('session_expired', { account });
                return null;
            }

            await this.refreshSession(account);
            this.currentAccount = account;
            return account;
        } catch (e) {
            console.warn('[SessionManager] getActiveAccount error:', e);
            return null;
        }
    }

    /**
     * Synchronous getter for current account (no validation)
     */
    getCurrentAccountSync() {
        return this.currentAccount;
    }

    /**
     * Check if session is valid
     * @param {string} account
     * @returns {Promise<boolean>}
     */
    async isSessionValid(account = null) {
        const targetAccount = account || this.currentAccount;
        if (!targetAccount) return false;

        try {
            const sessionData = await this.sessions.get(targetAccount);
            if (!sessionData) return false;
            return Date.now() < sessionData.expires_at;
        } catch (e) {
            return false;
        }
    }

    /**
     * Create a new session
     * @param {string} account
     * @param {object} options
     * @returns {Promise<string>} Session ID
     */
    async createSession(account, options = {}) {
        const normalizedAccount = normalizeAccount(account);
        if (!normalizedAccount) {
            throw new Error('Invalid account parameter for createSession');
        }

        const now = Date.now();
        // SECURITY FIX (v3.5.2): Use config timeout only — no 7-day fallback (fail-closed)
        const timeout = this.config.SESSION_TIMEOUT;
        if (!timeout || timeout <= 0) {
            throw new Error('SESSION_TIMEOUT not configured');
        }
        // SECURITY FIX (v3.5.2): Use CSPRNG for session IDs instead of Math.random()
        const sessionId = `${normalizedAccount}_${now}_${bytesToHex(getRandomBytes(16))}`;

        const sessionData = {
            account: normalizedAccount,
            sessionId,
            created_at: now,
            last_active: now,
            expires_at: now + timeout,
            userAgent: options.userAgent || 'unknown',
            loginType: options.loginType || 'unknown',
            pinEnabled: options.pinEnabled || false,
            quickLogin: options.quickLogin || false
        };

        // Use upsert pattern
        try {
            await this.sessions.add(sessionData, { id: normalizedAccount });
        } catch(e) {
            await this.sessions.update(normalizedAccount, sessionData);
        }

        try {
            await this.preferences.add({ account: normalizedAccount }, { id: 'active_account' });
        } catch(e) {
            await this.preferences.update('active_account', { account: normalizedAccount });
        }

        this.currentAccount = normalizedAccount;
        this.eventEmitter?.emit('session_created', {
            account: normalizedAccount,
            sessionId,
            pinEnabled: sessionData.pinEnabled
        });

        return sessionId;
    }

    /**
     * Update session properties
     * @param {object} updates
     * @returns {Promise<boolean>}
     */
    async updateSession(updates) {
        const account = this.currentAccount;
        if (!account) return false;

        try {
            const sessionData = await this.sessions.get(account);
            if (!sessionData) return false;

            await this.sessions.update(account, {
                ...sessionData,
                ...updates,
                last_active: Date.now()
            });
            return true;
        } catch (e) {
            console.warn('[SessionManager] updateSession error:', e);
            return false;
        }
    }

    /**
     * Refresh session expiration
     * @param {string} account
     * @returns {Promise<boolean>}
     */
    async refreshSession(account) {
        const normalizedAccount = normalizeAccount(account);
        if (!normalizedAccount) return false;

        const now = Date.now();
        // SECURITY FIX (v3.5.2): Consistent timeout — no 7-day fallback
        const timeout = this.config.SESSION_TIMEOUT || 30 * 60 * 1000;

        try {
            await this.sessions.update(normalizedAccount, {
                last_active: now,
                expires_at: now + timeout
            });
            return true;
        } catch (e) {
            console.warn('[SessionManager] refreshSession error:', e);
            return false;
        }
    }

    /**
     * Get current session data
     * @returns {Promise<object|null>}
     */
    async getCurrentSession() {
        try {
            let account = this.currentAccount;

            if (!account) {
                const pref = await this.preferences.get('active_account');
                account = pref?.account;
            }

            if (!account) return null;

            const sessionData = await this.sessions.get(account);
            return sessionData || null;
        } catch (e) {
            return null;
        }
    }

    /**
     * Clear current session
     * @returns {Promise<string|null>} Cleared account name
     */
    async clearSession() {
        try {
            // Get account to delete from both sources
            let accountToDelete = this.currentAccount;

            if (!accountToDelete) {
                try {
                    const pref = await this.preferences.get('active_account');
                    accountToDelete = pref?.account;
                } catch (e) {}
            }

            // Clear preference first
            try {
                await this.preferences.delete('active_account');
            } catch (e) {}

            // Then clear session
            if (accountToDelete) {
                try {
                    await this.sessions.delete(accountToDelete);
                } catch (e) {}
            }

            const clearedAccount = this.currentAccount;
            this.currentAccount = null;

            return clearedAccount;
        } catch(e) {
            console.warn('[SessionManager] clearSession error:', e);
            this.currentAccount = null;
            return null;
        }
    }

    /**
     * End session and emit event
     * @returns {Promise<string|null>}
     */
    async endSession() {
        const account = await this.clearSession();
        this.eventEmitter?.emit('session_ended', { account });
        return account;
    }

    /**
     * Get all stored sessions (for multi-account support)
     * @returns {Promise<object[]>}
     */
    async getAllSessions() {
        try {
            const sessions = await this.sessions.find({});
            return sessions.filter(s => Date.now() < s.expires_at);
        } catch (e) {
            return [];
        }
    }

    /**
     * Switch to a different account
     * @param {string} account
     * @returns {Promise<boolean>}
     */
    async switchAccount(account) {
        const normalizedAccount = normalizeAccount(account);
        if (!normalizedAccount) return false;

        try {
            const sessionData = await this.sessions.get(normalizedAccount);
            if (!sessionData || Date.now() > sessionData.expires_at) {
                return false;
            }

            await this.preferences.update('active_account', { account: normalizedAccount });
            this.currentAccount = normalizedAccount;
            await this.refreshSession(normalizedAccount);

            this.eventEmitter?.emit('account_switched', { account: normalizedAccount });
            return true;
        } catch (e) {
            console.warn('[SessionManager] switchAccount error:', e);
            return false;
        }
    }
}

// ============================================
// Exports
// ============================================

export default PixaProxyAPI;

// Error classes
export {
    CONFIG,
    PixaAPIError,
    KeyNotFoundError,
    VaultNotInitializedError,
    SessionExpiredError,
    SessionNotFoundError
};

// Re-export dpixa utilities for convenience
export {
    PrivateKey,
    PublicKey,
    Signature,
    Asset,
    Price,
    Memo,
    cryptoUtils,
    utils,
    Types,
    BlockchainMode,
    getVestingSharePrice,
    getVests,
    VERSION,
    DEFAULT_CHAIN_ID,
    NETWORK_ID
};

// Utility functions
export {
    normalizeAccount,
    getRandomBytes,
    bytesToHex,
    translateAssetFromChain,
    translateAssetToChain,
    parseAsset,
    formatAssetString
};

// Re-export SDK utility helpers
const { waitForEvent, retryingFetch } = utils;
export { waitForEvent, retryingFetch };

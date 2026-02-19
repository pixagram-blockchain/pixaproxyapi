# PixaProxyAPI Documentation

> 🚀 A high-level Pixa blockchain proxy layer with entity-based storage, WASM content sanitization, encrypted key vault, and session management. Built on top of `@pixagram/dpixa`.

**Version:** 3.4.0

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
  - [Entity Storage System](#entity-storage-system)
  - [Query Caching](#query-caching)
  - [Sanitization Pipeline](#sanitization-pipeline)
  - [Data Flow Diagram](#data-flow-diagram)
- [Getting Started](#getting-started)
  - [Installation](#installation)
  - [Initialization](#initialization)
  - [Configuration](#configuration)
- [Authentication & Sessions](#authentication--sessions)
  - [Quick Login](#quick-login)
  - [Vault & PIN](#vault--pin)
  - [Session Lifecycle](#session-lifecycle)
- [API Groups](#api-groups)
  - [database](#database-databaseapi)
  - [tags](#tags-tagsapi)
  - [blocks](#blocks-blocksapi)
  - [globals](#globals-globalsapi)
  - [accounts](#accounts-accountsapi)
  - [market](#market-marketapi)
  - [authority](#authority-authorityapi)
  - [votes](#votes-votesapi)
  - [content](#content-contentapi)
  - [witnesses](#witnesses-witnessesapi)
  - [follow](#follow-followapi)
  - [broadcast](#broadcast-broadcastapi)
  - [auth](#auth-authapi)
  - [formatter](#formatter-formatterapi)
  - [blockchain](#blockchain-blockchainapi)
  - [rc](#rc-resourcecreditsapi)
  - [communities](#communities-communitiesapi)
  - [keys](#keys-accountbykeyapi)
  - [transaction](#transaction-transactionstatusapi)
- [Content Sanitization](#content-sanitization)
  - [processPost](#processpost)
  - [processComment](#processcomment)
  - [extractPlainText](#extractplaintext)
  - [summarizeContent](#summarizecontent)
  - [parseMetadata](#parsemetadata)
  - [sanitizeBiography](#sanitizebiography)
  - [sanitizeUsername](#sanitizeusername)
- [Entity Storage Deep Dive](#entity-storage-deep-dive)
  - [Entity Types & Keys](#entity-types--keys)
  - [SanitizationPipeline](#sanitizationpipeline-class)
  - [EntityStoreManager](#entitystoremanager-class)
  - [QueryCacheManager](#querycachemanager-class)
  - [TTL Configuration](#ttl-configuration)
- [Events](#events)
- [Error Handling](#error-handling)
- [Exports](#exports)
- [Configuration Reference](#configuration-reference)

---

## Overview

`PixaProxyAPI` is the primary client-side interface for Pixagram applications that need to read from and write to the Pixa blockchain. It wraps the low-level `@pixagram/dpixa` client with:

- **Entity-based caching** — Accounts, posts, and comments are stored in typed LacertaDB collections, indexed by canonical IDs. Queries are cached as ID arrays and resolved from the entity stores on subsequent reads.
- **Automatic content sanitization** — Every entity passes through a WASM-powered sanitization pipeline (`pixa-content`) before entering the database. No raw, unsanitized content is ever served from cache.
- **Encrypted key vault** — Private keys can be stored in a PBKDF2-encrypted LacertaDB vault, unlocked with a user PIN.
- **Session management** — Multi-account sessions with expiration, refresh, and switch support.
- **Multi-strategy RPC fallback** — Each API method tries `condenser_api`, then `database_api`, then `pixamind` (Hivemind bridge), returning the first successful result.
- **Browser + Node.js** — Runs in both environments with automatic platform detection for crypto and stream APIs.

---

## Architecture

### Entity Storage System

Introduced in v3.4.0, the entity storage architecture replaces the flat key-value cache with a relational system that separates entities from queries.

```
┌─────────────────────────────────────────────────────────────────┐
│                     Entity Stores (LacertaDB)                   │
│                                                                 │
│  accounts_store        posts_store          comments_store      │
│  ┌──────────────┐     ┌──────────────────┐  ┌────────────────┐  │
│  │ key: "alice"  │     │ key: "alice_post" │  │ key: "bob_re1" │  │
│  │ display_name  │     │ html (sanitized)  │  │ html (strict)  │  │
│  │ sanitized_*   │     │ images, links     │  │ images, links  │  │
│  │ parsed_meta   │     │ plainText excerpt │  │ parsed_meta    │  │
│  │ reputation_*  │     │ tags, app         │  │ _stored_at     │  │
│  │ _stored_at    │     │ _stored_at        │  │                │  │
│  └──────────────┘     └──────────────────┘  └────────────────┘  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    Query Cache (LacertaDB)                       │
│                                                                 │
│  key: "trending:tag=art:limit=20"                               │
│  value: { ids: ["alice_post", "bob_photo", ...],                │
│           entity_type: "posts", timestamp: 1706000000 }         │
└─────────────────────────────────────────────────────────────────┘
```

### Query Caching

Query results are stored as **arrays of entity IDs** rather than duplicating full entity data. When a cached query is hit:

1. Look up the query key in `query_cache`
2. If fresh (within TTL), retrieve the ID array
3. Resolve each ID from the appropriate entity store
4. If all entities are present and fresh, return them directly — **zero RPC calls**
5. If any entity is stale or missing, re-fetch the entire query from chain

### Sanitization Pipeline

**Nothing enters an entity store without being sanitized first.** The `SanitizationPipeline` class processes raw blockchain data through the `pixa-content` WASM engine:

| Entity Type | Sanitization Applied |
|-------------|---------------------|
| **Account** | `parseMetadata` on `json_metadata` / `posting_json_metadata`, `sanitizeBiography` on bio, `sanitizeUsername` on name, profile image/cover extraction, reputation calculation |
| **Post** (depth=0) | `renderPost` (full Markdown→HTML, image extraction, link extraction, XSS filtering), `extractPlainText` (500-char excerpt), metadata parsing for tags/app |
| **Comment** (depth>0) | `renderComment` (stricter subset — no headings, tables, iframes), metadata parsing, reputation |

### Data Flow Diagram

```
  User calls api.tags.getDiscussionsByTrending({ tag: "art", limit: 20 })
      │
      ▼
  ┌──────────────────────────┐
  │ Build query cache key:   │
  │ "trending:tag=art:       │
  │  limit=20"               │
  └──────────┬───────────────┘
             │
      ┌──────▼──────┐          ┌──────────────┐
      │ Query Cache  │──fresh──▶│ Resolve IDs  │──▶ Return sanitized entities
      │ lookup       │          │ from entity  │
      └──────┬──────┘          │ stores       │
             │ stale/miss      └──────────────┘
             ▼
  ┌──────────────────────┐
  │ Fetch from chain     │  condenser_api → database_api → pixamind
  │ (multi-fallback)     │
  └──────────┬───────────┘
             ▼
  ┌──────────────────────┐
  │ SanitizationPipeline │  sanitizeContent() auto-detects post vs comment
  │ for each raw entity  │
  └──────────┬───────────┘
             ▼
  ┌──────────────────────┐
  │ Upsert into entity   │  posts_store / comments_store
  │ store + cache IDs    │  query_cache stores ID array
  └──────────┬───────────┘
             ▼
  Return sanitized entities
```

---

## Getting Started

### Installation

`PixaProxyAPI` requires the following peer dependencies:

```bash
npm install @pixagram/dpixa @pixagram/lacerta-db pixa-content
```

### Initialization

```js
import PixaProxyAPI from './pixaproxyapi.js';

const api = new PixaProxyAPI();

await api.initialize({
  // RPC nodes (optional — defaults to Pixagram's CORS proxy)
  nodes: [
    'https://api.pixagram.io',
    'https://api.hivekings.com'
  ],

  // Chain configuration (optional)
  chainId: 'your-chain-id',
  addressPrefix: 'PIX',

  // Timeouts
  timeout: 30000,
  failoverThreshold: 3,
  sessionTimeout: 30 * 60 * 1000,    // 30 minutes
  pinTimeout: 5 * 60 * 1000,          // 5 minutes

  // WASM sanitizer path (optional)
  wasmPath: '/path/to/pixa_content_bg.wasm',

  // Internal domains for link classification
  internalDomains: ['pixa.pics', 'pixagram.io'],

  // Performance monitoring (optional)
  enablePerformanceMonitoring: true,
});
```

After initialization, all API groups are available as properties on the instance:

```js
api.database      // DatabaseAPI
api.tags          // TagsAPI
api.blocks        // BlocksAPI
api.globals       // GlobalsAPI
api.accounts      // AccountsAPI
api.market        // MarketAPI
api.authority     // AuthorityAPI
api.votes         // VotesAPI
api.content       // ContentAPI
api.witnesses     // WitnessesAPI
api.follow        // FollowAPI
api.broadcast     // BroadcastAPI
api.auth          // AuthAPI
api.formatter     // FormatterAPI
api.blockchain    // BlockchainAPI
api.rc            // ResourceCreditsAPI
api.communities   // CommunitiesAPI
api.keys          // AccountByKeyAPI
api.transaction   // TransactionStatusAPI
```

### Configuration

You can update configuration at runtime:

```js
api.updateConfig({
  SESSION_TIMEOUT: 60 * 60 * 1000,   // 1 hour
  PIN_TIMEOUT: 10 * 60 * 1000,        // 10 minutes
  internalDomains: ['pixa.pics', 'app.pixagram.io'],

  // Override entity/query TTLs
  ENTITY_TTL: {
    accounts: 12 * 60 * 60 * 1000,   // 12 hours
    posts: 3 * 60 * 1000,             // 3 minutes
    comments: 60 * 1000,              // 1 minute
  },
  QUERY_TTL: {
    trending: 2 * 60 * 1000,          // 2 minutes
    feed: 15 * 1000,                   // 15 seconds
  }
});
```

---

## Authentication & Sessions

### Quick Login

The fastest way to authenticate. Keys are held in memory (not persisted to encrypted vault):

```js
// Login with master password
const result = await api.quickLogin('alice', 'masterpassword123', 'master', {
  userAgent: 'myapp/1.0',
});

console.log(result);
// {
//   success: true,
//   account: 'alice',
//   sessionId: 'alice_1706000000_abc123def',
//   keyType: 'master',
//   validation: { valid: true, publicKey: 'PIX7abc...', ... }
// }

// Login with individual WIF key
const result2 = await api.quickLogin('alice', '5KQwrPbwd...', 'posting');
```

### Vault & PIN

For persistent key storage, initialize the encrypted vault:

```js
// First time: create vault with PIN
await api.initializeVault('123456', {
  iterations: 1000000,     // PBKDF2 iterations (default: 1M)
  fastMode: false,         // true = 5000 iterations (dev only)
  onProgress: (pct) => console.log(`${pct}% derived`),
});

// Store keys in vault during login
await api.quickLogin('alice', 'masterpassword', 'master', {
  storeInVault: true,
});

// Later: unlock with PIN
const unlock = await api.unlockWithPin('123456', {
  keyType: 'posting',
  account: 'alice',
});
// { success: true, account: 'alice' }
```

### Session Lifecycle

```js
// Restore previous session on app start
const account = await api.restoreSession();
// Returns account name if session valid, null otherwise

// Check login status
const loggedIn = await api.isLoggedIn();

// Check if PIN unlock is needed
const status = await api.requiresUnlock('posting');
// { needsUnlock: false, unlockType: null, account: 'alice' }
// { needsUnlock: true, unlockType: 'pin', account: 'alice' }
// { needsUnlock: true, unlockType: 'key', account: 'alice' }

// Get active account
const active = await api.getActiveAccount();

// Logout
await api.logout();
```

---

## API Groups

### `database` (DatabaseAPI)

Low-level database API passthrough.

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `call(method, params)` | `string`, `any[]` | `Promise<any>` | Raw RPC call to `database_api` |
| `getDatabaseInfo()` | — | `Promise<object>` | Node database information |

```js
const info = await api.database.call('get_dynamic_global_properties', []);
```

---

### `tags` (TagsAPI)

Discussion discovery by sorting algorithm. **All discussion methods use entity store + query cache** (v3.4.0).

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `getTrendingTags(afterTag?, limit?)` | `string`, `number` | `Promise<Tag[]>` | Get trending tags |
| `getDiscussionsByTrending(query)` | `DiscussionQuery` | `Promise<Post[]>` | Trending discussions |
| `getDiscussionsByCreated(query)` | `DiscussionQuery` | `Promise<Post[]>` | Newest discussions |
| `getDiscussionsByHot(query)` | `DiscussionQuery` | `Promise<Post[]>` | Hot discussions |
| `getDiscussionsByPromoted(query)` | `DiscussionQuery` | `Promise<Post[]>` | Promoted discussions |
| `getDiscussionsByPayout(query)` | `DiscussionQuery` | `Promise<Post[]>` | Approaching payout |
| `getDiscussionsByVotes(query)` | `DiscussionQuery` | `Promise<Post[]>` | By vote count |
| `getDiscussionsByActive(query)` | `DiscussionQuery` | `Promise<Post[]>` | Recently active |
| `getDiscussionsByChildren(query)` | `DiscussionQuery` | `Promise<Post[]>` | By comment count |
| `getDiscussionsByMuted(query)` | `DiscussionQuery` | `Promise<Post[]>` | Muted (not available) |

**DiscussionQuery shape:**

```js
{
  tag: 'photography',       // Tag name or username
  limit: 20,                // Results count (max 100)
  start_author: '',         // Pagination cursor: author
  start_permlink: '',       // Pagination cursor: permlink
}
```

**Example:**

```js
// Get 20 trending posts in #pixelart
const posts = await api.tags.getDiscussionsByTrending({
  tag: 'pixelart',
  limit: 20,
});

// Each post is already sanitized with html, images, links, wordCount
posts.forEach(post => {
  console.log(post.title, post.wordCount, post.images.length);
  console.log(post.html); // Safe HTML, ready to render
});

// Paginate
const page2 = await api.tags.getDiscussionsByTrending({
  tag: 'pixelart',
  limit: 20,
  start_author: posts[posts.length - 1].author,
  start_permlink: posts[posts.length - 1].permlink,
});
```

---

### `blocks` (BlocksAPI)

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `getBlock(blockNum)` | `number` | `Promise<SignedBlock>` | Full block with transactions |
| `getBlockHeader(blockNum)` | `number` | `Promise<BlockHeader>` | Block header only |
| `getOpsInBlock(blockNum, onlyVirtual?)` | `number`, `boolean` | `Promise<AppliedOperation[]>` | Operations from a block |

```js
const block = await api.blocks.getBlock(12345678);
console.log(`Witness: ${block.witness}, Txs: ${block.transactions.length}`);
```

---

### `globals` (GlobalsAPI)

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `getDynamicGlobalProperties()` | — | `Promise<DynamicGlobalProperties>` | Current blockchain state |
| `getChainProperties()` | — | `Promise<ChainProperties>` | Witness-voted chain params |
| `getFeedHistory()` | — | `Promise<FeedHistory>` | PIXA/PXS price feed history |
| `getCurrentMedianHistoryPrice()` | — | `Promise<Price>` | Current median PIXA/PXS price |
| `getHardforkVersion()` | — | `Promise<string>` | Current hardfork version |
| `getRewardFund(name?)` | `string` | `Promise<RewardFund>` | Reward pool info |
| `getVestingDelegations(account, from?, limit?)` | `string`, `string`, `number` | `Promise<VestingDelegation[]>` | Delegations made by account |
| `getConfig()` | — | `Promise<object>` | Node compile-time config |
| `getVersion()` | — | `Promise<object>` | Node version info |

```js
const props = await api.globals.getDynamicGlobalProperties();
console.log(`Head block: ${props.head_block_number}`);
console.log(`PIXA supply: ${props.current_supply}`);

const price = await api.globals.getCurrentMedianHistoryPrice();
console.log(`1 PIXA = ${price.base} PXS`);
```

---

### `accounts` (AccountsAPI)

Account methods use the **entity store** — accounts are sanitized and cached with a 24-hour TTL by default.

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `getAccounts(accounts, forceRefresh?)` | `string[]`, `boolean` | `Promise<SanitizedAccount[]>` | Get detailed account info |
| `lookupAccounts(lowerBound, limit?)` | `string`, `number` | `Promise<string[]>` | Autocomplete account names |
| `lookupAccountNames(accounts)` | `string[]` | `Promise<Account[]>` | Lookup multiple accounts by name |
| `getAccountCount()` | — | `Promise<number>` | Total accounts on chain |
| `getAccountHistory(account, from?, limit?, bitmask?)` | `string`, `number`, `number`, `[number,number]` | `Promise<Array>` | Account operation history |
| `getAccountReputations(lowerBound?, limit?)` | `string`, `number` | `Promise<Array>` | Batch reputation lookup |
| `getAccountNotifications(account, limit?)` | `string`, `number` | `Promise<Notification[]>` | Account notifications (Pixamind) |

**Sanitized Account Properties (v3.4.0):**

Accounts returned from `getAccounts` include these extra fields produced by the sanitization pipeline:

```js
const [account] = await api.accounts.getAccounts(['alice']);

// Standard blockchain fields are all present (balance, vesting_shares, etc.)
// Plus sanitized fields:
account._entity_id          // 'alice'
account._entity_type        // 'account'
account._stored_at          // timestamp of DB insertion
account.reputation_score    // computed reputation (e.g. 65.42)
account.display_name        // sanitized from metadata profile.name
account.sanitized_about     // HTML-stripped bio (max 512 chars)
account.sanitized_name      // validated username
account.profile_image       // extracted profile image URL
account.cover_image         // extracted cover image URL
account.sanitized_location  // stripped location string
account.sanitized_website   // stripped website string
account.parsed_metadata     // { profile: {...}, tags: [...], extra: {...} }
```

```js
// Force refresh (bypasses entity store cache)
const fresh = await api.accounts.getAccounts(['alice'], true);
```

---

### `market` (MarketAPI)

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `getOrderBook(limit?)` | `number` | `Promise<OrderBook>` | Internal market order book |
| `getOpenOrders(account)` | `string` | `Promise<Order[]>` | Account's open orders |
| `getTicker()` | — | `Promise<Ticker>` | Market ticker |
| `getTradeHistory(start, end, limit?)` | `string`, `string`, `number` | `Promise<Trade[]>` | Recent trades |
| `getMarketHistory(bucketSeconds, start, end)` | `number`, `string`, `string` | `Promise<Bucket[]>` | OHLCV candles |
| `getMarketHistoryBuckets()` | — | `Promise<number[]>` | Available bucket sizes |

---

### `authority` (AuthorityAPI)

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `getOwnerHistory(account)` | `string` | `Promise<Array>` | Owner key change history |
| `getRecoveryRequest(account)` | `string` | `Promise<object\|null>` | Pending recovery request |
| `getWithdrawRoutes(account, type?)` | `string`, `string` | `Promise<Array>` | Power-down routes |
| `getAccountBandwidth(account, type)` | `string`, `string` | `Promise<object>` | Bandwidth usage |
| `getSavingsWithdrawFrom(account)` | `string` | `Promise<Array>` | Pending savings withdrawals (outgoing) |
| `getSavingsWithdrawTo(account)` | `string` | `Promise<Array>` | Pending savings deposits (incoming) |
| `verifyAuthority(stx)` | `SignedTransaction` | `Promise<boolean>` | Verify transaction signatures |

---

### `votes` (VotesAPI)

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `getActiveVotes(author, permlink)` | `string`, `string` | `Promise<Vote[]>` | Active votes on a post/comment |
| `getAccountVotes(account)` | `string` | `Promise<Vote[]>` | Votes cast by an account |

---

### `content` (ContentAPI)

Content methods use the **entity store + query cache**. Posts and comments are sanitized and cached separately.

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `getContent(author, permlink)` | `string`, `string` | `Promise<SanitizedPost\|SanitizedComment\|null>` | Single post or comment |
| `getContentReplies(author, permlink)` | `string`, `string` | `Promise<SanitizedComment[]>` | Replies to a post/comment |
| `getDiscussionsByAuthorBeforeDate(author, startPermlink, beforeDate, limit?)` | `string`, `string`, `string`, `number` | `Promise<SanitizedPost[]>` | Author's posts before date |
| `getRepliesByLastUpdate(author, startPermlink, limit?)` | `string`, `string`, `number` | `Promise<SanitizedComment[]>` | Replies by last update |
| `getDiscussionsByComments(query)` | `DiscussionQuery` | `Promise<SanitizedComment[]>` | User's comments |
| `getDiscussionsByBlog(query)` | `DiscussionQuery` | `Promise<SanitizedPost[]>` | User's blog posts |
| `getDiscussionsByFeed(query)` | `DiscussionQuery` | `Promise<SanitizedPost[]>` | User's feed |
| `getAccountPosts(account, sort?, limit?, options?)` | `string`, `string`, `number`, `object` | `Promise<SanitizedPost[]>` | Generic account posts |
| `getState(path)` | `string` | `Promise<any>` | Legacy state endpoint |

```js
// Fetch a single post (checks entity store first)
const post = await api.content.getContent('alice', 'my-pixel-art');

console.log(post.html);            // Sanitized HTML
console.log(post.images);          // [{ src, alt, is_base64, index }]
console.log(post.links);           // [{ href, text, domain, is_external }]
console.log(post.plainText);       // Plain text excerpt (max 500 chars)
console.log(post.tags);            // ['pixelart', 'art', 'creative']
console.log(post.author_reputation); // 67.5

// Fetch replies (cached as comment entities)
const replies = await api.content.getContentReplies('alice', 'my-pixel-art');
replies.forEach(reply => {
  console.log(`@${reply.author}: ${reply.html}`);
});
```

---

### `witnesses` (WitnessesAPI)

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `getWitnessByAccount(account)` | `string` | `Promise<Witness>` | Witness info for account |
| `getWitnessesByVote(from, limit?)` | `string`, `number` | `Promise<Witness[]>` | Witnesses ranked by votes |
| `lookupWitnessAccounts(lowerBound, limit?)` | `string`, `number` | `Promise<string[]>` | Autocomplete witness names |
| `getWitnessCount()` | — | `Promise<number>` | Total witness count |
| `getActiveWitnesses()` | — | `Promise<string[]>` | Current witness schedule |
| `getWitnessSchedule()` | — | `Promise<object>` | Detailed witness schedule |

---

### `follow` (FollowAPI)

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `getFollowers(account, startFollower?, type?, limit?)` | `string`, `string`, `string`, `number` | `Promise<Follow[]>` | Account followers |
| `getFollowing(account, startFollowing?, type?, limit?)` | `string`, `string`, `string`, `number` | `Promise<Follow[]>` | Accounts being followed |
| `getFollowCount(account)` | `string` | `Promise<{follower_count, following_count}>` | Follow counts |
| `getFeedEntries(account, startEntryId?, limit?)` | `string`, `number`, `number` | `Promise<FeedEntry[]>` | Feed entries |
| `getBlogEntries(account, startEntryId?, limit?)` | `string`, `number`, `number` | `Promise<BlogEntry[]>` | Blog entries |
| `getRebloggedBy(author, permlink)` | `string`, `string` | `Promise<string[]>` | Accounts that reblogged |
| `getBlogAuthors(account)` | `string` | `Promise<Array>` | Authors in user's blog |
| `getSubscriptions(account)` | `string` | `Promise<Array>` | Community subscriptions |

```js
const counts = await api.follow.getFollowCount('alice');
console.log(`Followers: ${counts.follower_count}, Following: ${counts.following_count}`);
```

---

### `broadcast` (BroadcastAPI)

All broadcast methods automatically retrieve the required private key from the key manager. The user must be logged in.

#### Content Operations

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `vote(voter, author, permlink, weight)` | `string`, `string`, `string`, `number` | `Promise<TransactionConfirmation>` | Vote on content (weight: -10000 to 10000) |
| `comment(params)` | `CommentParams` | `Promise<TransactionConfirmation>` | Create post or reply |
| `commentOptions(params)` | `CommentOptionsParams` | `Promise<TransactionConfirmation>` | Set beneficiaries, payout settings |
| `deleteComment(author, permlink)` | `string`, `string` | `Promise<TransactionConfirmation>` | Delete a post or comment |

```js
// Create a post
await api.broadcast.comment({
  parentAuthor: '',                  // Empty for root post
  parentPermlink: 'pixelart',       // Category
  author: 'alice',
  permlink: 'my-new-pixel-art',
  title: 'My New Pixel Art',
  body: '# Hello!\n\nCheck out this pixel art...',
  jsonMetadata: {
    tags: ['pixelart', 'art'],
    image: ['https://pixa.pics/image.png'],
    app: 'pixagram/3.4.0',
  },
});

// Vote 100%
await api.broadcast.vote('alice', 'bob', 'bobs-post', 10000);

// Set beneficiaries (must be called before first vote)
await api.broadcast.commentOptions({
  author: 'alice',
  permlink: 'my-new-pixel-art',
  maxAcceptedPayout: '1000000.000 PXS',
  percentPxs: 10000,
  allowVotes: true,
  allowCurationRewards: true,
  extensions: [[0, { beneficiaries: [{ account: 'pixagram', weight: 500 }] }]],
});
```

#### Transfer Operations

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `transfer(from, to, amount, memo?)` | `string`, `string`, `string`, `string` | `Promise<TransactionConfirmation>` | Transfer PIXA or PXS |
| `transferToVesting(from, to, amount)` | `string`, `string`, `string` | `Promise<TransactionConfirmation>` | Power up |
| `withdrawVesting(account, vestingShares)` | `string`, `string` | `Promise<TransactionConfirmation>` | Power down (use `"0.000000 VESTS"` to cancel) |
| `delegateVestingShares(delegator, delegatee, vestingShares)` | `string`, `string`, `string` | `Promise<TransactionConfirmation>` | Delegate/undelegate |
| `transferToSavings(from, to, amount, memo?)` | `string`, `string`, `string`, `string` | `Promise<TransactionConfirmation>` | Transfer to savings |
| `transferFromSavings(from, requestId, to, amount, memo?)` | `string`, `number`, `string`, `string`, `string` | `Promise<TransactionConfirmation>` | Initiate savings withdrawal (3-day) |
| `cancelTransferFromSavings(from, requestId)` | `string`, `number` | `Promise<TransactionConfirmation>` | Cancel pending withdrawal |
| `recurrentTransfer(params)` | `RecurrentParams` | `Promise<TransactionConfirmation>` | Set up recurring transfer |
| `claimRewardBalance(account, rewardPixa, rewardPxs, rewardVests)` | `string`, `string`, `string`, `string` | `Promise<TransactionConfirmation>` | Claim pending rewards |

```js
// Transfer 10 PIXA
await api.broadcast.transfer('alice', 'bob', '10.000 PIXA', 'Thanks!');

// Power up
await api.broadcast.transferToVesting('alice', 'alice', '100.000 PIXA');

// Claim all rewards
const [acc] = await api.accounts.getAccounts(['alice']);
await api.broadcast.claimRewardBalance(
  'alice',
  acc.reward_pixa_balance,
  acc.reward_pxs_balance,
  acc.reward_vesting_balance
);
```

#### Social Operations

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `follow(follower, following)` | `string`, `string` | `Promise<TransactionConfirmation>` | Follow a user |
| `unfollow(follower, following)` | `string`, `string` | `Promise<TransactionConfirmation>` | Unfollow a user |
| `mute(follower, following)` | `string`, `string` | `Promise<TransactionConfirmation>` | Mute a user |
| `reblog(account, author, permlink)` | `string`, `string`, `string` | `Promise<TransactionConfirmation>` | Reblog/resteem a post |
| `customJson(params)` | `CustomJsonParams` | `Promise<TransactionConfirmation>` | Broadcast custom JSON |

#### Account & Witness Operations

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `updateAccount2(params)` | `UpdateAccountParams` | `Promise<TransactionConfirmation>` | Update account (keys, metadata) |
| `updateProfile(account, profileObject)` | `string`, `object` | `Promise<TransactionConfirmation>` | Update profile metadata |
| `accountCreate(params)` | `AccountCreateParams` | `Promise<TransactionConfirmation>` | Create new account |
| `accountCreateWithDelegation(params)` | `AccountCreateWithDelegationParams` | `Promise<TransactionConfirmation>` | Create account with delegation |
| `accountWitnessVote(account, witness, approve?)` | `string`, `string`, `boolean` | `Promise<TransactionConfirmation>` | Vote for witness |
| `accountWitnessProxy(account, proxy)` | `string`, `string` | `Promise<TransactionConfirmation>` | Set witness proxy |
| `witnessUpdate(params)` | `WitnessUpdateParams` | `Promise<TransactionConfirmation>` | Update witness config |
| `setWithdrawVestingRoute(fromAccount, toAccount, percent, autoVest?)` | `string`, `string`, `number`, `boolean` | `Promise<TransactionConfirmation>` | Power-down routing |

#### Market Operations

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `limitOrderCreate(params)` | `LimitOrderParams` | `Promise<TransactionConfirmation>` | Create limit order |
| `limitOrderCancel(owner, orderId)` | `string`, `number` | `Promise<TransactionConfirmation>` | Cancel limit order |
| `convertPixa(owner, amount, requestId)` | `string`, `string`, `number` | `Promise<TransactionConfirmation>` | Convert PIXA to PXS |

#### Raw Operations

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `sendOperations(operations, key)` | `Array`, `PrivateKey\|string` | `Promise<TransactionConfirmation>` | Broadcast raw operations |

---

### `auth` (AuthAPI)

Cryptographic utilities (no RPC calls).

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `isWif(key)` | `string` | `boolean` | Check if string is a valid WIF private key |
| `toWif(username, password, role)` | `string`, `string`, `string` | `string` | Derive WIF from username/password/role |
| `wifToPublic(wif)` | `string` | `string` | Get public key from WIF |
| `signMessage(message, wif)` | `string`, `string` | `string` | Sign a message |
| `verifySignature(message, signature, publicKey)` | `string`, `string`, `string` | `boolean` | Verify a signature |
| `encodeMemo(senderPrivateKey, recipientPublicKey, message)` | `string`, `string`, `string` | `string` | Encrypt a memo |
| `decodeMemo(recipientPrivateKey, encryptedMemo)` | `string`, `string` | `string` | Decrypt a memo |
| `generateKeys(username, password)` | `string`, `string` | `KeySet` | Generate all 4 key pairs |

```js
// Generate all keys from master password
const keys = api.auth.generateKeys('alice', 'masterpassword');
// {
//   owner: '5K...', ownerPublic: 'PIX7...',
//   active: '5K...', activePublic: 'PIX7...',
//   posting: '5K...', postingPublic: 'PIX7...',
//   memo: '5K...', memoPublic: 'PIX7...',
// }
```

---

### `formatter` (FormatterAPI)

Formatting and conversion utilities.

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `reputation(rawReputation)` | `number` | `number` | Convert raw reputation to display score (e.g. 65.42) |
| `vestToSteem(vestingShares, totalVestingShares, totalVestingFundSteem)` | `string\|number` ×3 | `number` | Convert VESTS to PIXA |
| `steemToVest(steem, totalVestingShares, totalVestingFundSteem)` | `string\|number` ×3 | `number` | Convert PIXA to VESTS |
| `formatAsset(amount, symbol, precision?)` | `number`, `string`, `number` | `string` | Format asset string (e.g. `"100.000 PIXA"`) |
| `getVestingSharePrice(props)` | `DynamicGlobalProperties` | `Price` | VESTS↔PIXA price from global props |
| `getVests(account, subtractDelegated?, addReceived?)` | `Account`, `boolean`, `boolean` | `number` | Effective vesting shares |

---

### `blockchain` (BlockchainAPI)

Real-time blockchain streaming with async generators.

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `getBlockHeader(blockNum)` | `number` | `Promise<BlockHeader>` | Block header |
| `getBlock(blockNum)` | `number` | `Promise<SignedBlock>` | Full block |
| `getTransaction(txId)` | `string` | `Promise<SignedTransaction>` | Transaction by ID |
| `getTransactionHex(tx)` | `Transaction` | `Promise<string>` | Transaction hex encoding |
| `getCurrentBlockNum(mode?)` | `string` | `Promise<number>` | Current block number |
| `getCurrentBlockHeader(mode?)` | `string` | `Promise<BlockHeader>` | Current block header |
| `getCurrentBlock(mode?)` | `string` | `Promise<SignedBlock>` | Current full block |
| `getBlockNumbers(options?)` | `StreamOptions` | `AsyncGenerator<number>` | Stream block numbers |
| `getBlocks(options?)` | `StreamOptions` | `AsyncGenerator<SignedBlock>` | Stream full blocks |
| `getOperations(options?)` | `StreamOptions` | `AsyncGenerator<AppliedOperation>` | Stream all operations |
| `getBlockNumberStream()` | `StreamOptions` | `ReadableStream` | Node.js readable stream |
| `getBlockStream()` | `StreamOptions` | `ReadableStream` | Node.js readable stream |
| `getOperationsStream()` | `StreamOptions` | `ReadableStream` | Node.js readable stream |

**Mode:** `'irreversible'` (default, confirmed) or `'latest'` (may be reversed in fork).

```js
// Stream new operations
for await (const op of api.blockchain.getOperations()) {
  const [opType, opData] = op.op;

  if (opType === 'transfer') {
    console.log(`${opData.from} → ${opData.to}: ${opData.amount}`);
  }

  if (opType === 'vote') {
    console.log(`${opData.voter} voted ${opData.weight} on @${opData.author}/${opData.permlink}`);
  }
}

// Process a specific range
for await (const block of api.blockchain.getBlocks({ from: 1000000, to: 1000100 })) {
  console.log(`Block ${block.block_id}: ${block.transactions.length} txs`);
}
```

---

### `rc` (ResourceCreditsAPI)

Resource credits (transaction bandwidth) management.

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `getResourceParams()` | — | `Promise<object>` | Current RC parameters |
| `getResourcePool()` | — | `Promise<object>` | Global RC pool state |
| `findRcAccounts(accounts)` | `string[]` | `Promise<RCAccount[]>` | RC info for accounts |
| `getRCMana(account)` | `string` | `Promise<Manabar>` | Calculated RC mana (regenerated) |
| `getVPMana(account)` | `string` | `Promise<Manabar>` | Calculated voting power mana |
| `calculateRCCost(operationType, operationData?)` | `string`, `object` | `Promise<number>` | Estimate RC cost for an operation |

```js
const rc = await api.rc.getRCMana('alice');
console.log(`RC: ${rc.percentage}% (${rc.current_mana} / ${rc.max_mana})`);

const vp = await api.rc.getVPMana('alice');
console.log(`Voting Power: ${vp.percentage}%`);

const cost = await api.rc.calculateRCCost('comment', { body: 'Hello world!' });
console.log(`Estimated RC cost: ${cost}`);
```

---

### `communities` (CommunitiesAPI)

Community features (requires Pixamind/Hivemind). **Uses entity store + query cache** (v3.4.0).

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `getCommunity(name, observer?)` | `string`, `string` | `Promise<CommunityDetail\|null>` | Community details |
| `listCommunities(options?)` | `object` | `Promise<Community[]>` | List communities |
| `getSubscriptions(account)` | `string` | `Promise<Subscription[]>` | User's community subscriptions |
| `getRankedPosts(options?)` | `RankedPostsOptions` | `Promise<SanitizedPost[]>` | Ranked posts (cached + sanitized) |
| `getAccountPosts(account, sort?, options?)` | `string`, `string`, `object` | `Promise<SanitizedPost[]>` | Account posts (cached + sanitized) |

---

### `keys` (AccountByKeyAPI)

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `getKeyReferences(keys)` | `(string\|PublicKey)[]` | `Promise<{accounts: string[][]}>` | Find accounts by public key |

```js
const result = await api.keys.getKeyReferences(['PIX7abc123...']);
console.log(`Key belongs to: ${result.accounts[0].join(', ')}`);
```

---

### `transaction` (TransactionStatusAPI)

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `findTransaction(transactionId, expiration?)` | `string`, `string` | `Promise<{status: string}>` | Check transaction status |
| `isConfirmed(transactionId)` | `string` | `Promise<boolean>` | Whether transaction is confirmed |

Status values: `'within_irreversible_block'`, `'within_reversible_block'`, `'expired_irreversible'`, `'expired_reversible'`, `'too_old'`, `'unknown'`.

---

## Content Sanitization

The main `PixaProxyAPI` instance exposes convenience methods that delegate to the internal WASM-powered `ContentSanitizer`. In v3.4.0 these also delegate to `SanitizationPipeline` when available.

### processPost

Process a raw post through the full sanitization pipeline.

```js
const rawPost = await api.content.getContent('alice', 'my-post');
const processed = api.processPost(rawPost, {
  include_images: true,
  max_image_count: 0,          // 0 = unlimited
  internal_domains: ['pixa.pics'],
});

// processed.html         — sanitized HTML (XSS-safe)
// processed.images       — [{ src, alt, is_base64, index }]
// processed.links        — [{ href, text, domain, is_external }]
// processed.wordCount    — word count
// processed.plainText    — plain text excerpt
// processed.tags         — parsed tags array
// processed.author_reputation — computed reputation score
```

> **Note:** In v3.4.0, if the entity was already fetched through `api.content.*` or `api.tags.*`, it is already sanitized and `processPost` returns it as-is (no double-processing).

### processComment

Stricter sanitization for comments — no headings, tables, or iframes.

```js
const processed = api.processComment(rawComment);
```

### extractPlainText

Strip all HTML/Markdown formatting.

```js
const text = api.extractPlainText('# Hello\n\nSome **bold** text');
// "Hello Some bold text"
```

### summarizeContent

TF-IDF extractive summarization.

```js
const result = api.summarizeContent(longPostBody, 3);
// {
//   summary: 'Top 3 sentences...',
//   keywords: ['pixel', 'art', 'blockchain'],
//   sentences: [{ text, score }, ...]
// }
```

### parseMetadata

Parse `json_metadata` string (handles PIXA/HIVE/STEEM variants).

```js
const meta = api.parseMetadata(account.json_metadata);
// { profile: { name, about, ... }, tags: [...], extra: {...} }
```

### sanitizeBiography

HTML→plain text biography with length limit.

```js
const bio = api.sanitizeBiography('<p>Hello <b>world</b></p>', 128);
// "Hello world"
```

### sanitizeUsername

Validate and sanitize a username (3–16 chars, a-z0-9.-).

```js
api.sanitizeUsername('Alice.Smith')   // 'alice.smith'
api.sanitizeUsername('ab')            // '' (too short)
api.sanitizeUsername('INVALID!!')     // ''
```

---

## Entity Storage Deep Dive

### Entity Types & Keys

| Entity Type | Store Collection | Key Format | Example |
|-------------|-----------------|------------|---------|
| Account | `accounts_store` | `username` | `"alice"` |
| Post | `posts_store` | `${author}_${permlink}` | `"alice_my-pixel-art"` |
| Comment | `comments_store` | `${author}_${permlink}` | `"bob_re-alice-my-pixel-art-001"` |
| Query | `query_cache` | `${namespace}:${sorted_params}` | `"trending:limit=20:tag=art"` |

All entities carry metadata fields:

```js
{
  _entity_id: 'alice',          // Canonical key
  _entity_type: 'account',     // 'account' | 'post' | 'comment'
  _stored_at: 1706000000000,   // Insertion timestamp (ms)
  // ... all original + sanitized fields
}
```

### SanitizationPipeline Class

The pipeline is constructed with references to the `ContentSanitizer` and `FormatterAPI`:

| Method | Input | Output |
|--------|-------|--------|
| `sanitizeAccount(raw)` | Raw account from RPC | Account with `display_name`, `sanitized_about`, `parsed_metadata`, `reputation_score`, etc. |
| `sanitizePost(raw, options?)` | Raw discussion (depth=0) | Post with `html`, `images`, `links`, `wordCount`, `plainText`, `tags`, `app` |
| `sanitizeComment(raw, options?)` | Raw comment (depth>0) | Comment with `html` (strict), `images`, `links`, `wordCount` |
| `sanitizeContent(raw, options?)` | Any raw content | Auto-detects post vs comment by `depth` / `parent_author` |

### EntityStoreManager Class

| Method | Description |
|--------|-------------|
| `get(type, entityId)` | Get entity if fresh (within TTL), otherwise `null` |
| `upsert(type, sanitizedEntity)` | Insert or update a sanitized entity |
| `upsertMany(type, entities)` | Batch upsert |
| `resolve(type, ids[])` | Batch resolve — returns array in same order as IDs |
| `invalidate(type, entityId)` | Delete a single entity |
| `invalidateAll(type)` | Clear all entities of a type |

### QueryCacheManager Class

| Method | Description |
|--------|-------------|
| `QueryCacheManager.buildKey(namespace, params)` | **Static.** Build deterministic cache key from query descriptor |
| `get(queryKey, ttlCategory?)` | Retrieve cached ID array if fresh |
| `store(queryKey, ids[], entityType)` | Cache a query result as ID array |
| `invalidate(queryKey)` | Delete a single cached query |
| `invalidateByPrefix(prefix)` | Delete all queries matching a namespace |

### TTL Configuration

Default TTLs (all in milliseconds):

**Entity TTLs** (`ENTITY_TTL`):

| Entity | Default TTL | Description |
|--------|------------|-------------|
| `accounts` | 24 hours | Account data changes infrequently |
| `posts` | 5 minutes | Posts can receive votes/edits |
| `comments` | 2 minutes | Comments are more ephemeral |

**Query TTLs** (`QUERY_TTL`):

| Query Type | Default TTL | Description |
|-----------|------------|-------------|
| `trending` | 5 minutes | Trending algorithm changes slowly |
| `created` | 30 seconds | New posts appear frequently |
| `hot` | 3 minutes | Hot algorithm |
| `promoted` | 5 minutes | Promoted changes slowly |
| `active` | 1 minute | Activity-based |
| `blog` | 1 minute | User blog |
| `feed` | 30 seconds | User feed updates often |
| `comments` | 1 minute | Comment listings |
| `content` | 1 minute | Single content lookups |
| `content_replies` | 1 minute | Reply listings |
| `account_lookup` | 10 minutes | Account autocomplete |

---

## Events

Subscribe to events via `api.on()`, `api.off()`, `api.once()`:

| Event | Payload | Description |
|-------|---------|-------------|
| `session_created` | `{ account, sessionId, pinEnabled }` | New session started |
| `session_restored` | `{ account, pinEnabled, keysLoaded, needsPIN? }` | Previous session restored |
| `session_ended` | `{ account }` | Session terminated |
| `session_expired` | `{ account }` | Session TTL expired |
| `account_switched` | `{ account }` | Switched active account |
| `vault_initialized` | `{ timestamp }` | Encrypted vault created |
| `pin_unlocked` | `{ account }` | Vault unlocked with PIN |
| `key_required` | `{ account, type, callback }` | Key needed — UI should prompt user |
| `profile_updated` | `{ account, profile }` | Profile metadata updated |

```js
api.on('session_expired', ({ account }) => {
  console.log(`Session expired for @${account}`);
  // Redirect to login
});

api.on('key_required', async ({ account, type, callback }) => {
  // Show UI prompt for key
  const key = await showKeyPrompt(account, type);
  callback(key, false, false);
});
```

---

## Error Handling

All errors extend `PixaAPIError`:

| Error Class | Code | Description |
|-------------|------|-------------|
| `PixaAPIError` | varies | Base error with `code` and `data` properties |
| `KeyNotFoundError` | `KEY_NOT_FOUND` | Required key not available |
| `VaultNotInitializedError` | `VAULT_NOT_INITIALIZED` | Vault operation before init |
| `SessionExpiredError` | `SESSION_EXPIRED` | Session TTL exceeded |
| `SessionNotFoundError` | `SESSION_NOT_FOUND` | No active session |

```js
try {
  await api.broadcast.transfer('alice', 'bob', '10.000 PIXA', '');
} catch (error) {
  if (error instanceof KeyNotFoundError) {
    console.log(`Need ${error.data.keyType} key for @${error.data.account}`);
  } else if (error.code === 'SESSION_EXPIRED') {
    // Re-authenticate
  } else {
    console.error(error.message);
  }
}
```

---

## Exports

### Default Export

```js
import PixaProxyAPI from './pixaproxyapi.js';
```

### Named Exports

```js
// Error classes & config
import {
  CONFIG,
  PixaAPIError,
  KeyNotFoundError,
  VaultNotInitializedError,
  SessionExpiredError,
  SessionNotFoundError,
} from './pixaproxyapi.js';

// Re-exported from @pixagram/dpixa
import {
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
} from './pixaproxyapi.js';

// Utility functions
import {
  normalizeAccount,
  getRandomBytes,
  bytesToHex,
} from './pixaproxyapi.js';
```

---

## Configuration Reference

The full `CONFIG` object with defaults:

```js
{
  // Key derivation
  PBKDF2_ITERATIONS: 1_000_000,

  // Legacy cache TTLs (used by CacheManager for non-entity data)
  CACHE_TTL: {
    posts:        60_000,
    accounts:     86_400_000,
    comments:     60_000,
    trending:     300_000,
    feed:         30_000,
    communities:  3_600_000,
    rewards:      300_000,
    search:       600_000,
    blocks:       30_000,
    witnesses:    300_000,
    market:       60_000,
    global_props: 10_000,
  },

  // Entity store TTLs (v3.4.0)
  ENTITY_TTL: {
    accounts: 86_400_000,   // 24 hours
    posts:    300_000,       // 5 minutes
    comments: 120_000,       // 2 minutes
  },

  // Query cache TTLs (v3.4.0)
  QUERY_TTL: {
    trending:       300_000,
    created:        30_000,
    hot:            180_000,
    promoted:       300_000,
    active:         60_000,
    blog:           60_000,
    feed:           30_000,
    comments:       60_000,
    votes:          60_000,
    children:       60_000,
    cashout:        60_000,
    content:        60_000,
    content_replies: 60_000,
    account_lookup: 600_000,
    notifications:  30_000,
  },

  // Session & auth
  SESSION_TIMEOUT: 1_800_000,  // 30 minutes
  PIN_TIMEOUT:     300_000,     // 5 minutes
  MIN_PIN_LENGTH:  6,

  // Network
  DEFAULT_NODES: ['https://cors-header-proxy-with-api.omnibus-39a.workers.dev'],
  APP_NAME:       'pixagram/3.4.0',
  CHAIN_ID:       null,
  ADDRESS_PREFIX:  'PIX',

  // Pagination
  PAGINATION_LIMIT: 20,
}
```

---

*Pixagram SA — Share and Enjoy!* 🚀

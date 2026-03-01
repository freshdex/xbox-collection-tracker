-- 001_marketplace_tables.sql
-- Normalized marketplace tables for XCT Live scanner

-- Core product table: one row per product, all metadata
CREATE TABLE marketplace_products (
    product_id        VARCHAR(16) PRIMARY KEY,
    title             TEXT NOT NULL DEFAULT '',
    publisher         TEXT NOT NULL DEFAULT '',
    developer         TEXT NOT NULL DEFAULT '',
    category          TEXT NOT NULL DEFAULT '',
    release_date      DATE,
    platforms         TEXT[] NOT NULL DEFAULT '{}',
    product_kind      VARCHAR(32) NOT NULL DEFAULT '',
    xbox_title_id     VARCHAR(32) NOT NULL DEFAULT '',
    is_bundle         BOOLEAN NOT NULL DEFAULT FALSE,
    is_ea_play        BOOLEAN NOT NULL DEFAULT FALSE,
    xcloud_streamable BOOLEAN NOT NULL DEFAULT FALSE,
    capabilities      TEXT[] NOT NULL DEFAULT '{}',
    alternate_ids     JSONB NOT NULL DEFAULT '[]',
    image_tile        TEXT NOT NULL DEFAULT '',
    image_box_art     TEXT NOT NULL DEFAULT '',
    image_hero        TEXT NOT NULL DEFAULT '',
    short_description TEXT NOT NULL DEFAULT '',
    average_rating    REAL NOT NULL DEFAULT 0,
    rating_count      INTEGER NOT NULL DEFAULT 0,
    first_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sources           TEXT[] NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_mp_xbox_title_id ON marketplace_products(xbox_title_id) WHERE xbox_title_id != '';

-- Regional prices: 10 markets per product
CREATE TABLE marketplace_prices (
    product_id  VARCHAR(16) REFERENCES marketplace_products(product_id),
    market      VARCHAR(4) NOT NULL,
    currency    VARCHAR(4) NOT NULL,
    msrp        REAL NOT NULL DEFAULT 0,
    sale_price  REAL NOT NULL DEFAULT 0,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (product_id, market)
);

-- Channel/source membership
CREATE TABLE marketplace_channels (
    product_id  VARCHAR(16) REFERENCES marketplace_products(product_id),
    channel     VARCHAR(64) NOT NULL,
    regions     TEXT[] NOT NULL DEFAULT '{}',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (product_id, channel)
);

-- Manual admin tags (bundle overrides, grouping, hiding)
CREATE TABLE marketplace_tags (
    product_id  VARCHAR(16) NOT NULL,
    tag_type    VARCHAR(32) NOT NULL,
    tag_value   TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (product_id, tag_type)
);

-- Scan history
CREATE TABLE marketplace_scans (
    id                SERIAL PRIMARY KEY,
    started_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at      TIMESTAMPTZ,
    status            VARCHAR(16) NOT NULL DEFAULT 'running',
    scan_type         VARCHAR(32) NOT NULL DEFAULT 'full',
    channels_scanned  INTEGER DEFAULT 0,
    browse_products   INTEGER DEFAULT 0,
    catalog_enriched  INTEGER DEFAULT 0,
    prices_fetched    INTEGER DEFAULT 0,
    products_total    INTEGER DEFAULT 0,
    products_new      INTEGER DEFAULT 0,
    errors            JSONB DEFAULT '[]',
    duration_seconds  REAL
);

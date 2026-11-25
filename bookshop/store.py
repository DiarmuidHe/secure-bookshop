from contextlib import contextmanager
import sqlite3

from argon2 import PasswordHasher


# Use Argon2id to hash new passwords and check passwords at sign-in.
PASSWORD_HASHER = PasswordHasher(time_cost=2, memory_cost=19_456, parallelism=1)

# Run this SQL once when setting up a new shop database.
SCHEMA = """
-- Store each account's password hash, balance in cents and cart revision.
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    balance_cents INTEGER NOT NULL CHECK (balance_cents >= 0),
    cart_version INTEGER NOT NULL DEFAULT 0 CHECK (cart_version >= 0)
);
-- Keep book details and the prices the server uses at checkout.
CREATE TABLE books (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    author TEXT NOT NULL,
    price_cents INTEGER NOT NULL CHECK (price_cents > 0)
);
-- Link each customer to the books and quantities in their current cart.
CREATE TABLE cart (
    user_id INTEGER NOT NULL REFERENCES users(id),
    book_id INTEGER NOT NULL REFERENCES books(id),
    quantity INTEGER NOT NULL CHECK (quantity BETWEEN 1 AND 10),
    PRIMARY KEY (user_id, book_id)
);
-- Keep owner and date for lookup. The private order details are encrypted.
CREATE TABLE orders (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    nonce BLOB NOT NULL UNIQUE CHECK (length(nonce) = 12),
    ciphertext BLOB NOT NULL
);
CREATE INDEX orders_owner ON orders(user_id, created_at DESC, id DESC);
-- Keep a browser session's token digest, form token and expiry.
CREATE TABLE sessions (
    token_digest BLOB PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    csrf TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX session_expiry ON sessions(expires_at);
-- Count sign-in attempts for a client during a short time window.
CREATE TABLE login_limits (
    client_digest BLOB PRIMARY KEY,
    attempts INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX login_limit_expiry ON login_limits(expires_at);
-- Record an event and outcome with account and order IDs when available.
CREATE TABLE audit (
    id INTEGER PRIMARY KEY,
    occurred_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    event TEXT NOT NULL,
    outcome TEXT NOT NULL,
    actor_id INTEGER,
    order_id TEXT
);
"""

# Seed the catalogue with whole cents. For example, 2495 means $24.95.
BOOKS = (
    (1, "The Nature of Code", "Daniel Shiffman", 2495),
    (2, "A Philosophy of Software Design", "John Ousterhout", 2195),
    (3, "The Design of Everyday Things", "Don Norman", 1895),
    (4, "The Pragmatic Programmer", "David Thomas and Andrew Hunt", 3295),
    (5, "Designing Data-Intensive Applications", "Martin Kleppmann", 3895),
    (6, "Refactoring", "Martin Fowler", 2995),
)


# Open a transaction and close its connection when the caller finishes.
@contextmanager
def database(path, *, write=False):
    connection = sqlite3.connect(path, timeout=5)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        # Reserve the write slot before reading rows a write may depend on.
        connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        # SQLite commits on success and rolls back if an exception leaves this block.
        with connection:
            yield connection
    finally:
        connection.close()


# Create the tables and seed the catalogue and fictional accounts.
def create_database(path, accounts):
    # Store a password hash and start each account with $150.00.
    rows = [(name, PASSWORD_HASHER.hash(password), 15_000) for name, password in accounts]
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(SCHEMA)
        with connection:
            connection.executemany("INSERT INTO books VALUES (?, ?, ?, ?)", BOOKS)
            connection.executemany(
                "INSERT INTO users (username, password_hash, balance_cents) VALUES (?, ?, ?)", rows
            )
    finally:
        connection.close()


# Record the event as part of the caller's transaction.
def audit(connection, event, outcome, *, actor_id=None, order_id=None):
    connection.execute(
        "INSERT INTO audit (event, outcome, actor_id, order_id) VALUES (?, ?, ?, ?)",
        (event, outcome, actor_id, order_id),
    )


# Look up this customer's cart and join it to the catalogue prices.
def cart_items(connection, user_id):
    return connection.execute(
        """SELECT books.id, books.title, books.author, books.price_cents, cart.quantity
           FROM cart JOIN books ON cart.book_id = books.id
           WHERE cart.user_id = ? ORDER BY books.id""",
        (user_id,),
    ).fetchall()


# Return an order only when its ID and owner both match.
def owned_order(connection, user_id, order_id):
    return connection.execute(
        "SELECT * FROM orders WHERE user_id = ? AND id = ?", (user_id, order_id)
    ).fetchone()
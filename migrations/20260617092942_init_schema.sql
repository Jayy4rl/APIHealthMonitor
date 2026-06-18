CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(150) UNIQUE NOT NULL,
    password_hash VARCHAR(150) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE endpoints (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(150) NOT NULL,
    url VARCHAR(255) NOT NULL,
    check_interval_seconds INTEGER NOT NULL DEFAULT 60,
    created_at TIMESTAMPTZ DEFAULT now(),
    expected_status_code INTEGER NOT NULL DEFAULT 200,
    is_active BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE health_check (
    id SERIAL PRIMARY KEY,
    endpoint_id INTEGER NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    latency INTEGER,
    status_code INTEGER,
    health_status VARCHAR(20) NOT NULL,
    checked_at TIMESTAMPTZ DEFAULT now(),
    error_message VARCHAR(255)
);

CREATE TABLE webhook (
    id SERIAL PRIMARY KEY,
    endpoint_id INTEGER NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    target_url VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    is_active BOOLEAN NOT NULL DEFAULT true
);
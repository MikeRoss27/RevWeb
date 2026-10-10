// crates/webrev-storage/src/backends/sqlite.rs
//! The durable `SQLite` backend, using the runtime query API (no compile-time
//! schema, so no `DATABASE_URL` is required to build).

use crate::port::Storage;
use async_trait::async_trait;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use sqlx::Row;
use std::fmt::Display;
use std::path::Path;
use uuid::Uuid;
use webrev_core::{
    Confidence, Endpoint, EndpointScope, Finding, FindingKind, Method, Mission, Provenance, Result,
    SessionId, Source, WebrevError,
};

/// Embedded schema, applied (idempotently) on every connect.
const MIGRATION: &str = include_str!("../migrations/0001_init.sql");

fn storage_err<E: Display>(e: E) -> WebrevError {
    WebrevError::Storage(e.to_string())
}

/// A pooled `SQLite` connection implementing [`Storage`].
#[derive(Clone)]
pub struct SqliteStorage {
    pool: SqlitePool,
}

impl SqliteStorage {
    /// Open (creating if absent) the database at `path` and apply migrations.
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .map_err(storage_err)?;
        sqlx::raw_sql(MIGRATION)
            .execute(&pool)
            .await
            .map_err(storage_err)?;
        // Idempotent column add for databases created before `endpoints.scope`
        // existed. SQLite has no `ADD COLUMN IF NOT EXISTS`, so we run it
        // unconditionally and swallow the "duplicate column" error on DBs that
        // already have it (including freshly-created ones).
        if let Err(e) = sqlx::query("ALTER TABLE endpoints ADD COLUMN scope TEXT NOT NULL DEFAULT 'internal'")
            .execute(&pool)
            .await
        {
            if !e.to_string().contains("duplicate column name") {
                return Err(storage_err(e));
            }
        }
        // Same idempotent add for `findings.plaintext` (revealed secrets, opt-in
        // via `--reveal-secrets`). Nullable, defaults to NULL on older rows.
        if let Err(e) = sqlx::query("ALTER TABLE findings ADD COLUMN plaintext TEXT")
            .execute(&pool)
            .await
        {
            if !e.to_string().contains("duplicate column name") {
                return Err(storage_err(e));
            }
        }
        Ok(Self { pool })
    }
}

// --- enum <-> text mapping ------------------------------------------------
// The domain enums intentionally do not implement `FromStr` (that would push a
// parsing concern into the pure core), so the inverse of their `slug()` /
// `Display` lives here, at the persistence boundary.

fn parse_kind(s: &str) -> Result<FindingKind> {
    Ok(match s {
        "endpoint" => FindingKind::Endpoint,
        "secret" => FindingKind::Secret,
        "sourcemap" => FindingKind::SourceMap,
        "form" => FindingKind::Form,
        "link" => FindingKind::Link,
        "script" => FindingKind::Script,
        "route" => FindingKind::Route,
        "graphql" => FindingKind::GraphQl,
        "technology" => FindingKind::Technology,
        "parameter" => FindingKind::Parameter,
        "config" => FindingKind::Config,
        "ws_frame" => FindingKind::WebSocketFrame,
        other => return Err(WebrevError::Storage(format!("unknown finding kind {other:?}"))),
    })
}

fn parse_confidence(s: &str) -> Result<Confidence> {
    Ok(match s {
        "low" => Confidence::Low,
        "medium" => Confidence::Medium,
        "high" => Confidence::High,
        other => return Err(WebrevError::Storage(format!("unknown confidence {other:?}"))),
    })
}

fn parse_source(s: &str) -> Result<Source> {
    Ok(match s {
        "browser" => Source::Browser,
        "js-ast" => Source::JsAst,
        "js-regex" => Source::JsRegex,
        "html" => Source::Html,
        "sourcemap" => Source::SourceMap,
        "manifest" => Source::Manifest,
        other => return Err(WebrevError::Storage(format!("unknown source {other:?}"))),
    })
}

fn parse_endpoint_scope(s: &str) -> Result<EndpointScope> {
    Ok(match s {
        "internal" => EndpointScope::Internal,
        "external" => EndpointScope::External,
        other => return Err(WebrevError::Storage(format!("unknown endpoint scope {other:?}"))),
    })
}

#[async_trait]
impl Storage for SqliteStorage {
    async fn create_session(&self, mission: &Mission) -> Result<()> {
        sqlx::query("INSERT OR IGNORE INTO sessions (id, name) VALUES (?, ?)")
            .bind(mission.id.to_string())
            .bind(&mission.name)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    async fn insert_finding(&self, finding: &Finding) -> Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO findings \
             (id, session_id, kind, url, value, confidence, source, location, plaintext) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(finding.id.to_string())
        .bind(finding.session_id.to_string())
        .bind(finding.kind.slug())
        .bind(finding.url.as_deref())
        .bind(&finding.value)
        .bind(finding.confidence.slug())
        .bind(finding.provenance.source.to_string())
        .bind(finding.provenance.location.as_deref())
        .bind(finding.plaintext.as_deref())
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }

    async fn insert_endpoint(&self, session: SessionId, endpoint: &Endpoint) -> Result<()> {
        sqlx::query(
            "INSERT INTO endpoints (session_id, url, method, source, scope) VALUES (?, ?, ?, ?, ?)",
        )
            .bind(session.to_string())
            .bind(&endpoint.url)
            .bind(endpoint.method.to_string())
            .bind(endpoint.source.to_string())
            .bind(endpoint.scope.slug())
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    async fn insert_secret(&self, session: SessionId, fingerprint: &str) -> Result<()> {
        sqlx::query("INSERT INTO secrets (session_id, fingerprint) VALUES (?, ?)")
            .bind(session.to_string())
            .bind(fingerprint)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    async fn latest_session(&self) -> Result<Option<SessionId>> {
        let row = sqlx::query("SELECT id FROM sessions ORDER BY rowid DESC LIMIT 1")
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_err)?;
        match row {
            Some(row) => {
                let id: String = row.try_get("id").map_err(storage_err)?;
                Ok(Some(SessionId::parse(&id)?))
            }
            None => Ok(None),
        }
    }

    async fn findings_by_session(&self, session: SessionId) -> Result<Vec<Finding>> {
        let rows = sqlx::query(
            "SELECT id, session_id, kind, url, value, confidence, source, location, plaintext \
             FROM findings WHERE session_id = ? ORDER BY rowid",
        )
        .bind(session.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(storage_err)?;

        rows.into_iter()
            .map(|row| {
                let id: String = row.try_get("id").map_err(storage_err)?;
                let kind: String = row.try_get("kind").map_err(storage_err)?;
                let confidence: String = row.try_get("confidence").map_err(storage_err)?;
                let source: String = row.try_get("source").map_err(storage_err)?;
                let url: Option<String> = row.try_get("url").map_err(storage_err)?;
                let value: String = row.try_get("value").map_err(storage_err)?;
                let location: Option<String> = row.try_get("location").map_err(storage_err)?;
                let plaintext: Option<String> = row.try_get("plaintext").map_err(storage_err)?;
                Ok(Finding {
                    id: Uuid::parse_str(&id).map_err(storage_err)?,
                    session_id: session,
                    kind: parse_kind(&kind)?,
                    url,
                    value,
                    confidence: parse_confidence(&confidence)?,
                    provenance: Provenance::new(parse_source(&source)?, location),
                    plaintext,
                })
            })
            .collect()
    }

    async fn endpoints_by_session(&self, session: SessionId) -> Result<Vec<Endpoint>> {
        let rows = sqlx::query(
            "SELECT url, method, source, scope FROM endpoints WHERE session_id = ? ORDER BY rowid",
        )
        .bind(session.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(storage_err)?;

        rows.into_iter()
            .map(|row| {
                let url: String = row.try_get("url").map_err(storage_err)?;
                let method: String = row.try_get("method").map_err(storage_err)?;
                let source: String = row.try_get("source").map_err(storage_err)?;
                let scope: String = row.try_get("scope").map_err(storage_err)?;
                Ok(Endpoint::new(url, Method::parse(&method), parse_source(&source)?)
                    .with_scope(parse_endpoint_scope(&scope)?))
            })
            .collect()
    }

    async fn cleanup_session(&self, session: SessionId) -> Result<()> {
        let sid = session.to_string();
        for table in ["findings", "endpoints", "secrets"] {
            sqlx::query(&format!("DELETE FROM {table} WHERE session_id = ?"))
                .bind(&sid)
                .execute(&self.pool)
                .await
                .map_err(storage_err)?;
        }
        sqlx::query("DELETE FROM sessions WHERE id = ?")
            .bind(&sid)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrev_core::{FindingKind, Scope};

    #[tokio::test]
    async fn sqlite_round_trip_preserves_finding() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("webrev-test.db");
        let store = SqliteStorage::connect(&db).await.expect("connect");

        let mission = Mission::new("t", Scope::default(), vec![]);
        store.create_session(&mission).await.expect("session");

        let original = Finding::new(
            mission.id,
            FindingKind::Endpoint,
            Some("/api/x".into()),
            "GET /api/x",
            Confidence::High,
            Provenance::new(Source::JsAst, Some("app.js".into())),
        );
        store.insert_finding(&original).await.expect("insert");

        let back = store.findings_by_session(mission.id).await.expect("read");
        assert_eq!(back.len(), 1);
        assert_eq!(back[0], original);

        store.cleanup_session(mission.id).await.expect("cleanup");
        assert!(store.findings_by_session(mission.id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn sqlite_round_trips_revealed_secret_plaintext() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("webrev-secret.db");
        let store = SqliteStorage::connect(&db).await.expect("connect");

        let mission = Mission::new("t", Scope::default(), vec![]);
        store.create_session(&mission).await.expect("session");

        let secret = Finding::new(
            mission.id,
            FindingKind::Secret,
            None,
            "fp:deadbeefdeadbeef",
            Confidence::High,
            Provenance::new(Source::JsRegex, Some("app.js".into())),
        )
        .with_plaintext(Some("AKIAZ4XB7NMPQR2STUVW".into()));
        store.insert_finding(&secret).await.expect("insert");

        let back = store.findings_by_session(mission.id).await.expect("read");
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].plaintext.as_deref(), Some("AKIAZ4XB7NMPQR2STUVW"));
        assert_eq!(back[0], secret);
    }
}

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[cfg(embedded_cve_db)]
use std::io::Cursor;

use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection};
use serde::Serialize;
use serde_json::Value;
use walkdir::WalkDir;

const CVE_LIST_REPO: &str = "https://github.com/CVEProject/cvelistV5";
#[cfg(embedded_cve_db)]
const EMBEDDED_DB: &[u8] = include_bytes!("../assets/cve.db.zst");
const MAX_RESULTS: usize = 10;

#[derive(Debug, Clone, Serialize)]
pub struct CveRow {
    pub id: String,
    pub published: Option<String>,
    pub description: String,
    pub cvss_score: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductRow {
    pub cve_id: String,
    pub vendor: Option<String>,
    pub product: String,
    pub version_start: Option<String>,
    pub version_end: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CveShowRow {
    pub cve: CveRow,
    pub products: Vec<ProductRow>,
}

#[derive(Debug)]
struct ParsedCve {
    id: String,
    published: Option<String>,
    description: String,
    cvss_score: Option<f64>,
    products: Vec<ProductRow>,
}

pub fn ensure_local_db() -> Result<PathBuf> {
    let db_path = local_db_path()?;
    if db_path.exists() {
        return Ok(db_path);
    }

    let parent = db_path
        .parent()
        .context("failed to resolve CVE database parent directory")?;
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;

    #[cfg(embedded_cve_db)]
    {
        let db_bytes = decompress_embedded_db()?;
        fs::write(&db_path, db_bytes)
            .with_context(|| format!("failed to write {}", db_path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&db_path, fs::Permissions::from_mode(0o600))
                .with_context(|| format!("failed to set permissions on {}", db_path.display()))?;
        }

        return Ok(db_path);
    }

    #[cfg(not(embedded_cve_db))]
    {
        bail!(
            "this build does not contain an embedded CVE DB snapshot; run `opensus update-cve-db`"
        );
    }
}

pub fn rebuild_local_database() -> Result<PathBuf> {
    let tmp = tempfile::tempdir().context("failed to create temporary directory")?;
    let cloned = tmp.path().join("cvelistV5");
    let db_path = tmp.path().join("cve.db");
    let db_zst_path = tmp.path().join("cve.db.zst");

    clone_repo(&cloned)?;
    build_sqlite_from_repo(&cloned, &db_path)?;
    compress_db(&db_path, &db_zst_path)?;

    let target = local_db_path()?;
    let target_parent = target
        .parent()
        .context("failed to resolve CVE database parent directory")?;
    fs::create_dir_all(target_parent)
        .with_context(|| format!("failed to create {}", target_parent.display()))?;

    fs::copy(&db_path, &target)
        .with_context(|| format!("failed to replace {}", target.display()))?;
    Ok(target)
}

pub fn search_local_db(query: &str) -> Result<Vec<CveRow>> {
    let db_path = local_db_path()?;
    if !db_path.exists() {
        bail!(
            "CVE database does not exist at {}. Run `opensus init` first.",
            db_path.display()
        );
    }

    let conn = open_readonly_connection(&db_path)?;
    let like_query = format!("%{query}%");
    let mut stmt = conn.prepare(
        "WITH matches AS (
            SELECT c.id, c.published, c.description, c.cvss_score, bm25(cves_fts) AS rank
            FROM cves c
            JOIN cves_fts ON cves_fts.id = c.id
            WHERE cves_fts.description MATCH ?1
            UNION ALL
            SELECT c.id, c.published, c.description, c.cvss_score, 10.0 AS rank
            FROM cves c
            JOIN products p ON p.cve_id = c.id
            WHERE lower(p.product) LIKE lower(?2) OR lower(COALESCE(p.vendor, '')) LIKE lower(?2)
        )
        SELECT id, published, description, cvss_score
        FROM matches
        GROUP BY id
        ORDER BY MIN(rank), published DESC
        LIMIT ?3",
    )?;

    let rows = stmt.query_map(params![query, like_query, MAX_RESULTS as i64], |row| {
        Ok(CveRow {
            id: row.get(0)?,
            published: row.get(1)?,
            description: row.get(2)?,
            cvss_score: row.get(3)?,
        })
    })?;

    rows.collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to collect CVE search rows")
}

pub fn show_local_db(id: &str) -> Result<CveShowRow> {
    let db_path = local_db_path()?;
    if !db_path.exists() {
        bail!(
            "CVE database does not exist at {}. Run `opensus init` first.",
            db_path.display()
        );
    }

    let conn = open_readonly_connection(&db_path)?;
    let mut stmt = conn.prepare(
        "SELECT id, published, description, cvss_score
         FROM cves
         WHERE id = ?1",
    )?;
    let cve = stmt
        .query_row([id], |row| {
            Ok(CveRow {
                id: row.get(0)?,
                published: row.get(1)?,
                description: row.get(2)?,
                cvss_score: row.get(3)?,
            })
        })
        .with_context(|| format!("CVE `{id}` not found"))?;

    let mut product_stmt = conn.prepare(
        "SELECT cve_id, vendor, product, version_start, version_end
         FROM products
         WHERE cve_id = ?1
         ORDER BY product ASC",
    )?;

    let products = product_stmt
        .query_map([id], |row| {
            Ok(ProductRow {
                cve_id: row.get(0)?,
                vendor: row.get(1)?,
                product: row.get(2)?,
                version_start: row.get(3)?,
                version_end: row.get(4)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to collect product rows")?;

    Ok(CveShowRow { cve, products })
}

pub fn build_snapshot_to(output_path: &Path) -> Result<()> {
    let tmp = tempfile::tempdir().context("failed to create temporary directory")?;
    let cloned = tmp.path().join("cvelistV5");
    let db_path = tmp.path().join("cve.db");

    clone_repo(&cloned)?;
    build_sqlite_from_repo(&cloned, &db_path)?;
    compress_db(&db_path, output_path)?;
    Ok(())
}

fn clone_repo(target_dir: &Path) -> Result<()> {
    let output = Command::new("git")
        .args([
            "clone",
            CVE_LIST_REPO,
            target_dir.to_string_lossy().as_ref(),
        ])
        .output()
        .context("failed to execute git clone")?;

    if !output.status.success() {
        bail!(
            "git clone failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(())
}

fn build_sqlite_from_repo(repo_path: &Path, db_path: &Path) -> Result<()> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("failed to open SQLite database {}", db_path.display()))?;

    conn.execute_batch(
        "CREATE TABLE cves (
            id TEXT PRIMARY KEY,
            published TEXT,
            description TEXT,
            cvss_score REAL
        );
        CREATE TABLE products (
            cve_id TEXT,
            vendor TEXT,
            product TEXT,
            version_start TEXT,
            version_end TEXT
        );
        CREATE INDEX idx_products_product ON products(product);
        CREATE INDEX idx_products_vendor ON products(vendor);
        CREATE VIRTUAL TABLE cves_fts USING fts5(id, description);",
    )
    .context("failed to create SQLite schema")?;

    let tx = conn
        .unchecked_transaction()
        .context("failed to start transaction")?;

    let mut insert_cve = tx.prepare(
        "INSERT INTO cves (id, published, description, cvss_score)
         VALUES (?1, ?2, ?3, ?4)",
    )?;
    let mut insert_product = tx.prepare(
        "INSERT INTO products (cve_id, vendor, product, version_start, version_end)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;
    let mut insert_fts = tx.prepare(
        "INSERT INTO cves_fts (id, description)
         VALUES (?1, ?2)",
    )?;

    for entry in WalkDir::new(repo_path)
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        if entry.path().extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }

        let raw = fs::read_to_string(entry.path())
            .with_context(|| format!("failed to read {}", entry.path().display()))?;
        if let Some(cve) = parse_cve_json(&raw)? {
            insert_cve.execute(params![
                cve.id,
                cve.published,
                cve.description,
                cve.cvss_score
            ])?;

            for product in cve.products {
                insert_product.execute(params![
                    product.cve_id,
                    product.vendor,
                    product.product,
                    product.version_start,
                    product.version_end
                ])?;
            }

            insert_fts.execute(params![cve.id, cve.description])?;
        }
    }

    drop(insert_cve);
    drop(insert_product);
    drop(insert_fts);
    tx.commit().context("failed to commit SQLite transaction")?;

    conn.execute_batch("VACUUM;")
        .context("failed to vacuum SQLite database")?;

    Ok(())
}

fn compress_db(db_path: &Path, output_path: &Path) -> Result<()> {
    let input =
        fs::File::open(db_path).with_context(|| format!("failed to open {}", db_path.display()))?;
    let compressed = zstd::stream::encode_all(input, 19).context("zstd compression failed")?;
    fs::write(output_path, compressed)
        .with_context(|| format!("failed to write {}", output_path.display()))?;
    Ok(())
}

#[cfg(embedded_cve_db)]
fn decompress_embedded_db() -> Result<Vec<u8>> {
    match zstd::stream::decode_all(Cursor::new(EMBEDDED_DB)) {
        Ok(bytes) => Ok(bytes),
        Err(_) if EMBEDDED_DB.starts_with(b"SQLite format 3\0") => Ok(EMBEDDED_DB.to_vec()),
        Err(err) => Err(err).context("failed to decompress embedded CVE DB"),
    }
}

fn open_readonly_connection(db_path: &Path) -> Result<Connection> {
    let uri = format!("file:{}?mode=ro&immutable=1", db_path.to_string_lossy());
    Connection::open_with_flags(
        uri,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .with_context(|| format!("failed to open immutable SQLite DB {}", db_path.display()))
}

fn local_db_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME environment variable is required")?;
    Ok(PathBuf::from(home).join(".opensus").join("cve.db"))
}

fn parse_cve_json(raw: &str) -> Result<Option<ParsedCve>> {
    let v: Value = serde_json::from_str(raw).context("invalid CVE JSON")?;
    let id = v["cveMetadata"]["cveId"]
        .as_str()
        .unwrap_or_default()
        .trim();
    if id.is_empty() {
        return Ok(None);
    }

    let state = v["cveMetadata"]["state"].as_str().unwrap_or_default();
    if state.eq_ignore_ascii_case("REJECTED") {
        return Ok(None);
    }

    let description = v["containers"]["cna"]["descriptions"]
        .as_array()
        .and_then(|descriptions| {
            descriptions
                .iter()
                .find_map(|d| d["value"].as_str().map(str::trim))
                .or_else(|| {
                    descriptions
                        .first()
                        .and_then(|d| d["value"].as_str().map(str::trim))
                })
        })
        .filter(|text| !text.is_empty())
        .map(ToString::to_string);

    let Some(description) = description else {
        return Ok(None);
    };

    let products = parse_products(&v, id);
    if products.is_empty() {
        return Ok(None);
    }

    let published = v["cveMetadata"]["datePublished"]
        .as_str()
        .map(ToString::to_string)
        .or_else(|| {
            v["cveMetadata"]["dateUpdated"]
                .as_str()
                .map(ToString::to_string)
        });

    let cvss_score = extract_cvss_score(&v);

    Ok(Some(ParsedCve {
        id: id.to_string(),
        published,
        description,
        cvss_score,
        products,
    }))
}

fn parse_products(v: &Value, cve_id: &str) -> Vec<ProductRow> {
    let mut out = Vec::new();

    let Some(affected) = v["containers"]["cna"]["affected"].as_array() else {
        return out;
    };

    for item in affected {
        let product = item["product"].as_str().unwrap_or_default().trim();
        if product.is_empty() {
            continue;
        }

        let vendor = item["vendor"]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty());

        let mut inserted_with_version = false;
        if let Some(versions) = item["versions"].as_array() {
            for version in versions {
                let version_start = version["version"]
                    .as_str()
                    .map(str::trim)
                    .filter(|s| !s.is_empty() && *s != "*")
                    .map(ToString::to_string);
                let version_end = version["lessThanOrEqual"]
                    .as_str()
                    .or_else(|| version["lessThan"].as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToString::to_string);

                out.push(ProductRow {
                    cve_id: cve_id.to_string(),
                    vendor: vendor.map(ToString::to_string),
                    product: product.to_string(),
                    version_start,
                    version_end,
                });
                inserted_with_version = true;
            }
        }

        if !inserted_with_version {
            out.push(ProductRow {
                cve_id: cve_id.to_string(),
                vendor: vendor.map(ToString::to_string),
                product: product.to_string(),
                version_start: None,
                version_end: None,
            });
        }
    }

    out
}

fn extract_cvss_score(v: &Value) -> Option<f64> {
    let metrics = v["containers"]["cna"]["metrics"].as_array()?;
    for metric in metrics {
        for key in [
            "cvssV4_0", "cvssV40", "cvssV3_1", "cvssV31", "cvssV3_0", "cvssV30",
        ] {
            if let Some(score) = metric[key]["baseScore"].as_f64() {
                return Some(score);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_filters_rejected_records() {
        let raw = r#"{
          "cveMetadata": {"cveId":"CVE-2024-0001","state":"REJECTED"},
          "containers": {"cna": {"descriptions":[{"value":"x"}], "affected":[{"product":"nginx"}]}}
        }"#;

        let parsed = parse_cve_json(raw).expect("parse should succeed");
        assert!(parsed.is_none());
    }

    #[test]
    fn parse_requires_description_and_products() {
        let raw = r#"{
          "cveMetadata": {"cveId":"CVE-2024-0002","state":"PUBLISHED"},
          "containers": {"cna": {"descriptions":[], "affected":[{"product":"nginx"}]}}
        }"#;
        assert!(parse_cve_json(raw).expect("parse should succeed").is_none());

        let raw_no_products = r#"{
          "cveMetadata": {"cveId":"CVE-2024-0003","state":"PUBLISHED"},
          "containers": {"cna": {"descriptions":[{"value":"desc"}], "affected":[]}}
        }"#;
        assert!(parse_cve_json(raw_no_products)
            .expect("parse should succeed")
            .is_none());
    }

    #[test]
    fn parse_extracts_minimal_fields() {
        let raw = r#"{
          "cveMetadata": {
            "cveId":"CVE-2024-0004",
            "state":"PUBLISHED",
            "datePublished":"2024-01-20T10:00:00.000Z"
          },
          "containers": {
            "cna": {
              "descriptions":[{"lang":"en","value":"Buffer overflow in nginx module"}],
              "affected":[{"vendor":"nginx","product":"nginx","versions":[{"version":"1.24.0","lessThan":"1.24.4"}]}],
              "metrics":[{"cvssV31":{"baseScore":8.6}}]
            }
          }
        }"#;

        let parsed = parse_cve_json(raw)
            .expect("parse should succeed")
            .expect("record should be kept");

        assert_eq!(parsed.id, "CVE-2024-0004");
        assert_eq!(parsed.description, "Buffer overflow in nginx module");
        assert_eq!(parsed.cvss_score, Some(8.6));
        assert_eq!(parsed.products.len(), 1);
        assert_eq!(parsed.products[0].product, "nginx");
        assert_eq!(parsed.products[0].version_start.as_deref(), Some("1.24.0"));
        assert_eq!(parsed.products[0].version_end.as_deref(), Some("1.24.4"));
    }
}

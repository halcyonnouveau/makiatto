use std::env;
use std::fs::DirEntry;
use std::path::Path;
use std::process::Command;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let db_path = Path::new(&out_dir).join("schema.db");

    // Set DATABASE_URL for sqlx
    println!("cargo:rustc-env=DATABASE_URL=sqlite:{}", db_path.display());
    let _ = std::fs::remove_file(&db_path);

    let migrations_dir = Path::new("migrations");
    let mut migration_files = std::fs::read_dir(migrations_dir)
        .expect("Failed to read migrations directory")
        .collect::<Result<Vec<_>, _>>()
        .expect("Failed to collect migration files");

    migration_files.sort_by_key(DirEntry::file_name);

    let mut combined_sql = String::new();
    for entry in migration_files {
        if let Some(ext) = entry.path().extension()
            && ext == "sql"
        {
            let content =
                std::fs::read_to_string(entry.path()).expect("Failed to read migration file");
            combined_sql.push_str(&content);
            combined_sql.push('\n');
        }
    }

    let output = Command::new("sqlite3")
        .arg(&db_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(stdin) = child.stdin.as_mut() {
                stdin.write_all(combined_sql.as_bytes())?;
            }
            child.wait_with_output()
        });

    match output {
        Ok(output) if !output.status.success() => {
            println!(
                "cargo:warning=sqlite3 failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(_) => {}
        Err(e) => {
            println!("cargo:warning=Failed to run sqlite3 (is it installed?): {e}",);
        }
    }
}

use std::env;
use std::fs::DirEntry;
use std::io::Write;
use std::path::Path;
use std::process::Command;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap_or_else(|_| {
        std::env::temp_dir()
            .join("makiatto-build")
            .to_string_lossy()
            .to_string()
    });
    let out_path = Path::new(&out_dir);

    std::fs::create_dir_all(out_path).expect("Failed to create output directory");

    let db_path = out_path.join("schema.db");

    // Set DATABASE_URL for sqlx
    println!("cargo:rustc-env=DATABASE_URL=sqlite:{}", db_path.display());
    let _ = std::fs::remove_file(&db_path);

    println!("cargo:rerun-if-changed=build.rs");

    let schemas_dir = Path::new("schemas");
    // rerun if schema files are added or removed
    println!("cargo:rerun-if-changed={}", schemas_dir.display());

    let mut schema_files = std::fs::read_dir(schemas_dir)
        .expect("Failed to read schemas directory")
        .collect::<Result<Vec<_>, _>>()
        .expect("Failed to collect schema files");

    schema_files.sort_by_key(DirEntry::file_name);

    let mut combined_sql = String::new();
    for entry in schema_files {
        let path = entry.path();
        if let Some(ext) = path.extension()
            && ext == "sql"
        {
            // rerun if any individual schema file's contents change
            println!("cargo:rerun-if-changed={}", path.display());
            let content = std::fs::read_to_string(&path).expect("Failed to read schema file");
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
            println!("cargo:warning=Failed to run sqlite3 (is it installed?): {e}");
        }
    }
}

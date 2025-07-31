use anyhow::Error;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::process::Command;
use tower_lsp::async_trait;
use tower_lsp::lsp_types::{Diagnostic, DiagnosticSeverity, Position, Range};

#[async_trait]
trait Compiler: Send + Sync {
    async fn compile(&self, file: &str) -> Result<Value, Error>;
    async fn lint(&self, file: &str) -> Result<serde_json::Value, Error>;
}

struct ForgeCompiler;

#[derive(Debug, Deserialize, Serialize)]
struct ForgeLintDiagnostic {
    #[serde(rename = "$message_type")]
    message_type: String,
    message: String,
    code: Option<ForgeLintCode>,
    level: String,
    spans: Vec<ForgeLintSpan>,
    children: Vec<ForgeLintChild>,
    rendered: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ForgeLintCode {
    code: String,
    explanation: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ForgeLintSpan {
    file_name: String,
    byte_start: u32,
    byte_end: u32,
    line_start: u32,
    line_end: u32,
    column_start: u32,
    column_end: u32,
    is_primary: bool,
    text: Vec<ForgeLintText>,
    label: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ForgeLintText {
    text: String,
    highlight_start: u32,
    highlight_end: u32,
}

#[derive(Debug, Deserialize, Serialize)]
struct ForgeLintChild {
    message: String,
    code: Option<String>,
    level: String,
    spans: Vec<ForgeLintSpan>,
    children: Vec<ForgeLintChild>,
    rendered: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ForgeCompileError {
    #[serde(rename = "sourceLocation")]
    source_location: ForgeSourceLocation,
    #[serde(rename = "type")]
    error_type: String,
    component: String,
    severity: String,
    #[serde(rename = "errorCode")]
    error_code: String,
    message: String,
    #[serde(rename = "formattedMessage")]
    formatted_message: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ForgeSourceLocation {
    file: String,
    start: i32,  // Changed to i32 to handle -1 values
    end: i32,    // Changed to i32 to handle -1 values
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ForgeCompileOutput {
    errors: Option<Vec<ForgeCompileError>>,
    sources: serde_json::Value,
    contracts: serde_json::Value,
    build_infos: Vec<serde_json::Value>,
}

pub async fn run_forge_lint_and_get_diagnostics(
    file_path: &str,
) -> anyhow::Result<Vec<Diagnostic>> {
    let compiler = ForgeCompiler;
    let lint_output = compiler.lint(file_path).await?;
    let diagnostics = forge_lint_to_lsp_diagnostics(&lint_output, file_path);
    Ok(diagnostics)
}

pub async fn run_forge_compile_and_get_diagnostics(
    file_path: &str,
) -> anyhow::Result<Vec<Diagnostic>> {
    let compiler = ForgeCompiler;
    let compile_output = compiler.compile(file_path).await;

    match compile_output {
        Ok(json) => {
            // Successful compilation, but check for warnings
            match serde_json::from_value::<ForgeCompileOutput>(json) {
                Ok(compile_output) => {
                    let diagnostics = forge_compile_to_lsp_diagnostics(&compile_output, file_path);
                    Ok(diagnostics)
                }
                Err(_) => Ok(Vec::new()),
            }
        }
        Err(e) => {
            // Parse the error message to extract JSON
            let error_str = e.to_string();
            if let Some(json_start) = error_str.find('{') {
                let json_part = &error_str[json_start..];
                match serde_json::from_str::<ForgeCompileOutput>(json_part) {
                    Ok(compile_output) => {
                        let diagnostics =
                            forge_compile_to_lsp_diagnostics(&compile_output, file_path);
                        Ok(diagnostics)
                    }
                    Err(_) => {
                        // Fallback: create a generic error diagnostic
                        Ok(vec![Diagnostic {
                            range: Range {
                                start: Position {
                                    line: 0,
                                    character: 0,
                                },
                                end: Position {
                                    line: 0,
                                    character: 0,
                                },
                            },
                            severity: Some(DiagnosticSeverity::ERROR),
                            code: None,
                            code_description: None,
                            source: Some("forge-compile".to_string()),
                            message: error_str,
                            related_information: None,
                            tags: None,
                            data: None,
                        }])
                    }
                }
            } else {
                // Fallback: create a generic error diagnostic
                Ok(vec![Diagnostic {
                    range: Range {
                        start: Position {
                            line: 0,
                            character: 0,
                        },
                        end: Position {
                            line: 0,
                            character: 0,
                        },
                    },
                    severity: Some(DiagnosticSeverity::ERROR),
                    code: None,
                    code_description: None,
                    source: Some("forge-compile".to_string()),
                    message: error_str,
                    related_information: None,
                    tags: None,
                    data: None,
                }])
            }
        }
    }
}

pub fn forge_lint_to_lsp_diagnostics(
    forge_output: &serde_json::Value,
    target_file: &str,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();

    if let serde_json::Value::Array(items) = forge_output {
        for item in items {
            if let Ok(forge_diag) = serde_json::from_value::<ForgeLintDiagnostic>(item.clone()) {
                // Only include diagnostics for the target file
                for span in &forge_diag.spans {
                    if span.file_name.ends_with(target_file) && span.is_primary {
                        let diagnostic = Diagnostic {
                            range: Range {
                                start: Position {
                                    line: (span.line_start - 1) as u32,        // LSP is 0-based
                                    character: (span.column_start - 1) as u32, // LSP is 0-based
                                },
                                end: Position {
                                    line: (span.line_end - 1) as u32,
                                    character: (span.column_end - 1) as u32,
                                },
                            },
                            severity: Some(match forge_diag.level.as_str() {
                                "error" => DiagnosticSeverity::ERROR,
                                "warning" => DiagnosticSeverity::WARNING,
                                "note" => DiagnosticSeverity::INFORMATION,
                                "help" => DiagnosticSeverity::HINT,
                                _ => DiagnosticSeverity::INFORMATION,
                            }),
                            code: forge_diag.code.as_ref().map(|c| {
                                tower_lsp::lsp_types::NumberOrString::String(c.code.clone())
                            }),
                            code_description: None,
                            source: Some("forge-lint".to_string()),
                            message: forge_diag.message.clone(),
                            related_information: None,
                            tags: None,
                            data: None,
                        };
                        diagnostics.push(diagnostic);
                        break; // Only take the first primary span per diagnostic
                    }
                }
            }
        }
    }

    diagnostics
}

pub fn forge_compile_to_lsp_diagnostics(
    forge_output: &ForgeCompileOutput,
    target_file: &str,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();

    if let Some(errors) = &forge_output.errors {
        for error in errors {
            if error.source_location.file.ends_with(target_file) {
                // Convert byte positions to line/column positions
                let (start_line, start_col) =
                    byte_to_line_col(&error.source_location.file, error.source_location.start);
                let (end_line, end_col) =
                    byte_to_line_col(&error.source_location.file, error.source_location.end);

                let diagnostic = Diagnostic {
                    range: Range {
                        start: Position {
                            line: start_line,
                            character: start_col,
                        },
                        end: Position {
                            line: end_line,
                            character: end_col,
                        },
                    },
                    severity: Some(match error.severity.as_str() {
                        "error" => DiagnosticSeverity::ERROR,
                        "warning" => DiagnosticSeverity::WARNING,
                        "info" => DiagnosticSeverity::INFORMATION,
                        _ => DiagnosticSeverity::ERROR,
                    }),
                    code: Some(tower_lsp::lsp_types::NumberOrString::String(
                        error.error_code.clone(),
                    )),
                    code_description: None,
                    source: Some("forge-compile".to_string()),
                            message: error.message.clone(),                    related_information: None,
                    tags: None,
                    data: None,
                };
                diagnostics.push(diagnostic);
            }
        }
    }

    diagnostics
}

fn byte_to_line_col(file_path: &str, byte_pos: i32) -> (u32, u32) {
    use std::fs;
    
    // Handle special case where byte_pos is -1 (indicates whole file)
    if byte_pos == -1 {
        return (0, 0); // Position at start of file for whole-file diagnostics
    }
    
    // Convert to usize for array indexing
    let byte_pos = byte_pos as usize;
    
    match fs::read_to_string(file_path) {
        Ok(content) => {
            let bytes = content.as_bytes();
            let mut line = 0u32;
            let mut col = 0u32;
            
            for (i, &byte) in bytes.iter().enumerate() {
                if i >= byte_pos {
                    break;
                }
                
                if byte == b'\n' {
                    line += 1;
                    col = 0;
                } else {
                    col += 1;
                }
            }
            
            (line, col)
        }
        Err(_) => (0, 0), // Fallback if file can't be read
    }
}
#[async_trait]
impl Compiler for ForgeCompiler {
    async fn lint(&self, file: &str) -> anyhow::Result<serde_json::Value> {
        let output = Command::new("forge")
            .arg("lint")
            .arg(file)
            .arg("--json")
            .output()
            .await?;

        // forge lint outputs JSON to stderr, not stdout
        let stderr_str = String::from_utf8_lossy(&output.stderr);

        // Parse JSON output line by line
        let mut diagnostics = Vec::new();
        for line in stderr_str.lines() {
            if line.trim().is_empty() {
                continue;
            }

            // Parse each line as JSON
            match serde_json::from_str::<serde_json::Value>(line) {
                Ok(value) => diagnostics.push(value),
                Err(e) => {
                    eprintln!("Failed to parse JSON line: {}, error: {}", line, e);
                    continue;
                }
            }
        }

        Ok(serde_json::Value::Array(diagnostics))
    }

    async fn compile(&self, file: &str) -> anyhow::Result<Value> {
        let output = Command::new("forge")
            .arg("compile")
            .arg(file)
            .arg("--json")
            .arg("--no-cache")
            .output()
            .await?;

        let json_output: Value = serde_json::from_slice(&output.stdout)?;

        // Check if there are compilation errors (not warnings) in the JSON output
        if let Some(errors) = json_output.get("errors") {
            if let Some(error_array) = errors.as_array() {
                let has_errors = error_array.iter().any(|error| {
                    if let Some(severity) = error.get("severity") {
                        if let Some(severity_str) = severity.as_str() {
                            return severity_str == "error";
                        }
                    }
                    false
                });

                if has_errors {
                    // Return the JSON with errors as an error
                    anyhow::bail!("{}", serde_json::to_string(&json_output)?);
                }
            }
}
        Ok(json_output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    async fn run_compilation(compiler: &dyn Compiler, file: &str) -> Result<Value, Error> {
        compiler.compile(file).await
    }
    #[tokio::test]
    async fn test_compile_valid_file() {
        println!("Running compilation!");
        let compiler = ForgeCompiler;
        let result = run_compilation(&compiler, "contracts/A.sol").await;

        assert!(
            result.is_ok(),
            "Expected compile to succeed, got: {:?}",
            result
        );
        let json = result.unwrap();
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
        assert!(json.is_object(), "Expected JSON output to be an object");
    }

    #[tokio::test]
    async fn test_compile_invalid_file() {
        let compiler = ForgeCompiler;

        let result = compiler.compile("contracts/NonExistent.sol").await;

        assert!(result.is_err(), "Expected compile to fail for invalid file");
    }

    #[tokio::test]
    async fn test_lint_valid_file() {
        let compiler = ForgeCompiler;
        let result = compiler.lint("contracts/A.sol").await;

        assert!(result.is_ok(), "Expected lint to succeed");
        let json_value = result.unwrap();

        println!(
            "Lint output:\n{}",
            serde_json::to_string_pretty(&json_value).unwrap()
        );

        assert!(json_value.is_array(), "Expected lint output to be an array");
    }

    #[tokio::test]
    async fn test_forge_lint_to_lsp_diagnostics() {
        let compiler = ForgeCompiler;
        let result = compiler.lint("contracts/A.sol").await;

        assert!(result.is_ok(), "Expected lint to succeed");
        let json_value = result.unwrap();

        let diagnostics = forge_lint_to_lsp_diagnostics(&json_value, "contracts/A.sol");

        println!("LSP Diagnostics: {:#?}", diagnostics);

        assert!(!diagnostics.is_empty(), "Expected at least one diagnostic");

        // Check the first diagnostic
        let first_diag = &diagnostics[0];
        assert_eq!(first_diag.source, Some("forge-lint".to_string()));
        assert_eq!(
            first_diag.message,
            "function names should use mixedCase"
        );
        assert_eq!(
            first_diag.severity,
            Some(tower_lsp::lsp_types::DiagnosticSeverity::INFORMATION)
        );

        // Check position (should be 0-based for LSP)
        assert_eq!(first_diag.range.start.line, 6); // line 7 in 1-based becomes 6 in 0-based
        assert_eq!(first_diag.range.start.character, 13); // column 14 in 1-based becomes 13 in 0-based
    }

    #[tokio::test]
    async fn test_compile_compilation_error_file() {
        let compiler = ForgeCompiler;
        let result = compiler.compile("contracts/CompilationError.sol").await;

        assert!(
            result.is_err(),
            "Expected compile to fail for CompilationError.sol"
        );

        let error_str = result.unwrap_err().to_string();
        println!("Compilation error: {}", error_str);

        // Check that the error contains expected JSON structure
        assert!(
            error_str.contains("ParserError"),
            "Expected ParserError in output"
        );
        assert!(
            error_str.contains("Expected identifier but got ';'"),
            "Expected specific error message"
        );
    }

    #[tokio::test]
    async fn test_run_forge_compile_and_get_diagnostics() {
        let diagnostics =
            run_forge_compile_and_get_diagnostics("contracts/CompilationError.sol").await;

        assert!(
            diagnostics.is_ok(),
            "Expected diagnostics extraction to succeed"
        );
        let diag_vec = diagnostics.unwrap();

        println!("Compilation diagnostics: {:#?}", diag_vec);

        assert!(
            !diag_vec.is_empty(),
            "Expected at least one compilation diagnostic"
        );

        let first_diag = &diag_vec[0];
        assert_eq!(first_diag.source, Some("forge-compile".to_string()));
        assert_eq!(
            first_diag.severity,
            Some(tower_lsp::lsp_types::DiagnosticSeverity::ERROR)
        );
        assert_eq!(
            first_diag.message,
            "Expected identifier but got ';'"
        );
        assert_eq!(
            first_diag.code,
            Some(tower_lsp::lsp_types::NumberOrString::String(
                "2314".to_string()
            ))
        );

        // Check that position is reasonable (line 5 is 0-based for line 6 where errrrror; is)
        assert_eq!(first_diag.range.start.line, 5);
        assert!(first_diag.range.start.character > 0);
    }

    #[tokio::test]
    async fn test_forge_compile_to_lsp_diagnostics() {
        // Create a mock ForgeCompileOutput with the expected structure
        let mock_error = ForgeCompileError {
            source_location: ForgeSourceLocation {
                file: "contracts/CompilationError.sol".to_string(),
                start: 104,
                end: 105,
            },
            error_type: "ParserError".to_string(),
            component: "general".to_string(),
            severity: "error".to_string(),
            error_code: "2314".to_string(),
            message: "Expected identifier but got ';'".to_string(),
            formatted_message: "ParserError: Expected identifier but got ';'\n --> contracts/CompilationError.sol:6:13:\n  |\n6 |     errrrror;\n  |             ^\n\n".to_string(),
        };

        let mock_output = ForgeCompileOutput {
            errors: Some(vec![mock_error]),
            sources: serde_json::Value::Object(serde_json::Map::new()),
            contracts: serde_json::Value::Object(serde_json::Map::new()),
            build_infos: vec![],
        };

        let diagnostics =
            forge_compile_to_lsp_diagnostics(&mock_output, "contracts/CompilationError.sol");

        println!("Mock compilation diagnostics: {:#?}", diagnostics);

        assert_eq!(diagnostics.len(), 1);
        let diag = &diagnostics[0];

        assert_eq!(diag.source, Some("forge-compile".to_string()));
        assert_eq!(
            diag.severity,
            Some(tower_lsp::lsp_types::DiagnosticSeverity::ERROR)
        );
        assert_eq!(
            diag.message,
            "Expected identifier but got ';'"
        );
        assert_eq!(
            diag.code,
            Some(tower_lsp::lsp_types::NumberOrString::String(
                "2314".to_string()
            ))
        );
    }

    #[tokio::test]
    async fn test_compile_warnings_to_lsp_diagnostics() {
        // Test that compilation warnings are also converted to LSP diagnostics
        let diagnostics = run_forge_compile_and_get_diagnostics("contracts/A.sol").await;

        assert!(
            diagnostics.is_ok(),
            "Expected diagnostics extraction to succeed"
        );
        let diag_vec = diagnostics.unwrap();

        println!("Compilation warnings as diagnostics: {:#?}", diag_vec);

        // A.sol should have warnings, not errors
        assert!(
            !diag_vec.is_empty(),
            "Expected at least one compilation warning diagnostic"
        );

        // Check that warnings are properly converted
        let warning_diag = &diag_vec[0];
        assert_eq!(warning_diag.source, Some("forge-compile".to_string()));
        assert_eq!(
            warning_diag.severity,
            Some(tower_lsp::lsp_types::DiagnosticSeverity::WARNING)
        );
        assert!(
            warning_diag
                .message
                .contains("Unused function parameter")
                || warning_diag
                    .message
                    .contains("Unused local variable")
        );
    }

    #[tokio::test]
    async fn test_empty_file_diagnostics() {
        println!("Testing empty Solidity file diagnostics...");
        
        // Test that empty files generate SPDX and pragma warnings
        let diagnostics = run_forge_compile_and_get_diagnostics("contracts/Empty.sol").await;

        assert!(
            diagnostics.is_ok(),
            "Expected diagnostics extraction to succeed for empty file"
        );
        let diag_vec = diagnostics.unwrap();

        println!("Empty file diagnostics: {:#?}", diag_vec);

        // Empty file should have warnings for SPDX and pragma
        assert!(
            !diag_vec.is_empty(),
            "Expected warnings for empty Solidity file"
        );

        // Check for SPDX warning
        let has_spdx_warning = diag_vec.iter().any(|d| {
            d.message.contains("SPDX license identifier not provided") &&
            d.severity == Some(tower_lsp::lsp_types::DiagnosticSeverity::WARNING) &&
            d.source == Some("forge-compile".to_string())
        });
        assert!(has_spdx_warning, "Should have SPDX license identifier warning");

        // Check for pragma warning
        let has_pragma_warning = diag_vec.iter().any(|d| {
            d.message.contains("does not specify required compiler version") &&
            d.severity == Some(tower_lsp::lsp_types::DiagnosticSeverity::WARNING) &&
            d.source == Some("forge-compile".to_string())
        });
        assert!(has_pragma_warning, "Should have pragma version warning");

        println!("✅ Empty file diagnostics working correctly:");
        for (i, diag) in diag_vec.iter().enumerate() {
            println!("   {}. [{}] {}", 
                i + 1, 
                diag.source.as_ref().unwrap_or(&"unknown".to_string()),
                diag.message
            );
            println!("      Code: {:?}, Severity: {:?}", diag.code, diag.severity);
            println!("      Position: line {}, col {}", diag.range.start.line, diag.range.start.character);
        }
    }

    #[tokio::test]
    async fn test_diagnostic_lsp_compliance() {
        println!("🔍 Testing LSP Diagnostic compliance...");
        
        // Test with different types of files to get various diagnostics
        let test_cases = vec![
            ("contracts/CompilationError.sol", "compilation errors"),
            ("contracts/A.sol", "compilation warnings"),
            ("contracts/Empty.sol", "empty file warnings"),
        ];
        
        for (file_path, description) in test_cases {
            println!("\n📁 Testing {} ({})", file_path, description);
            
            // Get compilation diagnostics
            let compile_result = run_forge_compile_and_get_diagnostics(file_path).await;
            if let Ok(compile_diags) = compile_result {
                println!("   📊 Compilation diagnostics: {}", compile_diags.len());
                for (i, diag) in compile_diags.iter().enumerate() {
                    println!("   {}. LSP Diagnostic Structure:", i + 1);
                    println!("      ✅ range: {:?}", diag.range);
                    println!("      ✅ severity: {:?} (LSP values: Error=1, Warning=2, Info=3, Hint=4)", diag.severity);
                    println!("      ✅ code: {:?}", diag.code);
                    println!("      ✅ source: {:?}", diag.source);
                    println!("      ✅ message: \"{}\"", diag.message);
                    println!("      ✅ tags: {:?}", diag.tags);
                    println!("      ✅ related_information: {:?}", diag.related_information);
                    println!("      ✅ data: {:?}", diag.data);
                    
                    // Verify required fields according to LSP spec
                    assert!(diag.range.start.line >= 0, "Range start line should be >= 0");
                    assert!(diag.range.start.character >= 0, "Range start character should be >= 0");
                    assert!(diag.range.end.line >= 0, "Range end line should be >= 0");
                    assert!(diag.range.end.character >= 0, "Range end character should be >= 0");
                    assert!(!diag.message.is_empty(), "Message should not be empty");
                    
                    // Check severity values match LSP spec
                    if let Some(severity) = diag.severity {
                        match severity {
                            DiagnosticSeverity::ERROR => println!("      ✅ Severity: Error (1)"),
                            DiagnosticSeverity::WARNING => println!("      ✅ Severity: Warning (2)"),
                            DiagnosticSeverity::INFORMATION => println!("      ✅ Severity: Information (3)"),
                            DiagnosticSeverity::HINT => println!("      ✅ Severity: Hint (4)"),
                            _ => println!("      ⚠️  Severity: Unknown ({:?})", severity),
                        }
                    }
                }
            }
            
            // Get linting diagnostics (if applicable)
            if file_path != "contracts/Empty.sol" {
                let lint_result = run_forge_lint_and_get_diagnostics(file_path).await;
                if let Ok(lint_diags) = lint_result {
                    println!("   📊 Linting diagnostics: {}", lint_diags.len());
                    for (i, diag) in lint_diags.iter().take(2).enumerate() { // Show first 2
                        println!("   Lint {}. Message: \"{}\"", i + 1, diag.message);
                        println!("           Severity: {:?}, Code: {:?}", diag.severity, diag.code);
                    }
                }
            }
        }
        
        println!("\n✅ LSP Diagnostic compliance check completed!");
    }

    #[tokio::test]
    async fn test_comprehensive_diagnostic_capture() {
        println!("🔍 Testing comprehensive diagnostic capture...");
        
        // Test that we capture ALL types of diagnostics that forge can produce
        let test_cases = vec![
            ("contracts/CompilationError.sol", vec!["Expected identifier"]),
            ("contracts/A.sol", vec!["Unused function parameter", "Unused local variable"]),
            ("contracts/Empty.sol", vec!["SPDX license identifier", "compiler version"]),
        ];
        
        for (file_path, expected_keywords) in test_cases {
            println!("\n📁 Testing comprehensive capture for: {}", file_path);
            
            // Run forge compile directly to see what it produces
            println!("   🔧 Running forge compile directly...");
            let output = Command::new("forge")
                .arg("compile")
                .arg(file_path)
                .arg("--json")
                .arg("--no-cache")
                .output()
                .await
                .expect("Should run forge compile");
            
            let stdout_str = String::from_utf8_lossy(&output.stdout);
            println!("   📊 Forge compile JSON length: {} bytes", stdout_str.len());
            
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout_str) {
                if let Some(errors) = json.get("errors") {
                    if let Some(error_array) = errors.as_array() {
                        println!("   📊 Forge reports {} errors/warnings", error_array.len());
                        for (i, error) in error_array.iter().enumerate() {
                            if let Some(message) = error.get("message") {
                                println!("      {}. {}", i + 1, message.as_str().unwrap_or("Unknown"));
                            }
                        }
                    }
                }
            }
            
            // Now test our diagnostic capture
            println!("   🔧 Testing our diagnostic capture...");
            let diagnostics = run_forge_compile_and_get_diagnostics(file_path).await;
            
            match diagnostics {
                Ok(diag_vec) => {
                    println!("   ✅ Captured {} diagnostics", diag_vec.len());
                    
                    // Check that we captured diagnostics for expected keywords
                    for keyword in expected_keywords {
                        let found = diag_vec.iter().any(|d| d.message.contains(keyword));
                        if found {
                            println!("   ✅ Found diagnostic containing: '{}'", keyword);
                        } else {
                            println!("   ❌ Missing diagnostic containing: '{}'", keyword);
                            // Print all messages to help debug
                            for (i, diag) in diag_vec.iter().enumerate() {
                                println!("      {}: {}", i + 1, diag.message);
                            }
                        }
                        assert!(found, "Should find diagnostic containing '{}'", keyword);
                    }
                }
                Err(e) => {
                    println!("   ❌ Failed to capture diagnostics: {}", e);
                    panic!("Should capture diagnostics for {}", file_path);
                }
            }
        }
        
        println!("\n✅ Comprehensive diagnostic capture test completed!");
    }
}

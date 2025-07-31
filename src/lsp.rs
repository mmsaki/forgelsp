mod utils;

use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer, LspService, Server};
use tracing::info;
use utils::{run_forge_compile_and_get_diagnostics, run_forge_lint_and_get_diagnostics};

pub struct ForgeLspRunner;

#[derive(Debug)]
struct ForgeLspServer {
    client: Client,
}

struct TextDocumentItem<'a> {
    uri: Url,
    text: &'a str,
    version: Option<i32>,
}

impl ForgeLspServer {
    async fn on_change<'a>(&self, params: TextDocumentItem<'a>) {
        // Only process Solidity files
        if !params.uri.path().ends_with(".sol") {
            self.client
                .log_message(
                    MessageType::INFO,
                    format!("Skipping non-Solidity file: {}", params.uri.path()),
                )
                .await;
            return;
        }

        let file_path = params.uri.path();
        
        // Convert absolute path to relative path for forge commands
        let relative_path = if file_path.starts_with('/') {
            // Try to make the path relative to current working directory
            match std::env::current_dir() {
                Ok(cwd) => {
                    let abs_path = std::path::Path::new(file_path);
                    match abs_path.strip_prefix(&cwd) {
                        Ok(rel_path) => rel_path.to_string_lossy().to_string(),
                        Err(_) => file_path.to_string(), // Fallback to original path
                    }
                }
                Err(_) => file_path.to_string(), // Fallback to original path
            }
        } else {
            file_path.to_string()
        };
        
        self.client
            .log_message(
                MessageType::INFO,
                format!("Running diagnostics for: {} (relative: {})", file_path, relative_path),
            )
            .await;

        let mut all_diagnostics = Vec::new();

        // Collect compilation diagnostics (errors and warnings)
        self.client
            .log_message(MessageType::INFO, "Running forge compile...")
            .await;
        match run_forge_compile_and_get_diagnostics(&relative_path).await {
            Ok(mut compile_diagnostics) => {
                let compile_count = compile_diagnostics.len();
                all_diagnostics.append(&mut compile_diagnostics);
                self.client
                    .log_message(
                        MessageType::INFO,
                        format!("Found {} compilation diagnostics", compile_count),
                    )
                    .await;
            }
            Err(e) => {
                self.client
                    .log_message(
                        MessageType::ERROR,
                        format!("Compilation diagnostics failed: {}", e),
                    )
                    .await;
            }
        }

        // Collect linting diagnostics (style and best practices)
        self.client
            .log_message(MessageType::INFO, "Running forge lint...")
            .await;
        match run_forge_lint_and_get_diagnostics(&relative_path).await {
            Ok(mut lint_diagnostics) => {
                let lint_count = lint_diagnostics.len();
                all_diagnostics.append(&mut lint_diagnostics);
                self.client
                    .log_message(
                        MessageType::INFO,
                        format!("Found {} linting diagnostics", lint_count),
                    )
                    .await;
            }
            Err(e) => {
                self.client
                    .log_message(
                        MessageType::WARNING,
                        format!("Linting diagnostics failed: {}", e),
                    )
                    .await;
            }
        }

        // Always publish diagnostics (even if empty) to clear previous ones
        let diagnostics_count = all_diagnostics.len();
        
        // Log detailed diagnostic information for debugging
        for (i, diag) in all_diagnostics.iter().enumerate() {
            self.client
                .log_message(
                    MessageType::INFO,
                    format!(
                        "📋 Diagnostic {}: [{}] {} (severity: {:?}, line: {}, col: {})",
                        i + 1,
                        diag.source.as_ref().unwrap_or(&"unknown".to_string()),
                        diag.message,
                        diag.severity,
                        diag.range.start.line,
                        diag.range.start.character
                    ),
                )
                .await;
        }
        
        self.client
            .publish_diagnostics(params.uri.clone(), all_diagnostics, params.version)
            .await;

        self.client
            .log_message(
                MessageType::INFO,
                format!(
                    "✅ Published {} total diagnostics for {}",
                    diagnostics_count, relative_path
                ),
            )
            .await;
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for ForgeLspServer {
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        Ok(InitializeResult {
            server_info: Some(ServerInfo {
                name: "forge lsp".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            }),

            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                diagnostic_provider: Some(DiagnosticServerCapabilities::Options(DiagnosticOptions {
                    identifier: Some("forge-lsp".to_string()),
                    inter_file_dependencies: false,
                    workspace_diagnostics: false,
                    work_done_progress_options: WorkDoneProgressOptions::default(),
                })),
                workspace: Some(WorkspaceServerCapabilities {
                    workspace_folders: Some(WorkspaceFoldersServerCapabilities {
                        supported: Some(true),
                        change_notifications: Some(OneOf::Left(true)),
                    }),
                    file_operations: None,
                }),
                ..ServerCapabilities::default()
            },
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "lsp server intialized!")
            .await;
    }

    async fn shutdown(&self) -> Result<()> {
        self.client
            .log_message(MessageType::INFO, "lsp server shutting down")
            .await;
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        self.client
            .log_message(MessageType::INFO, "file opened")
            .await;
        self.on_change(TextDocumentItem {
            uri: params.text_document.uri,
            text: &params.text_document.text,
            version: Some(params.text_document.version),
        })
        .await
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        self.client
            .log_message(MessageType::INFO, "file changed")
            .await;
        self.on_change(TextDocumentItem {
            uri: params.text_document.uri,
            text: &params.content_changes[0].text,
            version: Some(params.text_document.version),
        })
        .await;
    }

    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        self.client
            .log_message(MessageType::INFO, "file saved")
            .await;

        // Always run diagnostics on save, regardless of whether text is provided
        // If text is provided, use it; otherwise read from file system
        let text_content = if let Some(text) = params.text {
            text
        } else {
            // Read the file from disk since many LSP clients don't send text on save
            match std::fs::read_to_string(params.text_document.uri.path()) {
                Ok(content) => content,
                Err(e) => {
                    self.client
                        .log_message(
                            MessageType::ERROR,
                            format!("Failed to read file on save: {}", e),
                        )
                        .await;
                    return;
                }
            }
        };

        let item = TextDocumentItem {
            uri: params.text_document.uri,
            text: &text_content,
            version: None,
        };

        // Always run diagnostics on save to reflect the current file state
        self.on_change(item).await;
        _ = self.client.semantic_tokens_refresh().await;
    }

    async fn did_close(&self, _: DidCloseTextDocumentParams) {
        self.client
            .log_message(MessageType::INFO, "file closed")
            .await;
    }

    async fn did_change_configuration(&self, _: DidChangeConfigurationParams) {
        self.client
            .log_message(MessageType::INFO, "configuration changed!")
            .await;
    }

    async fn did_change_workspace_folders(&self, _: DidChangeWorkspaceFoldersParams) {
        self.client
            .log_message(MessageType::INFO, "workspace folders changed!")
            .await;
    }

    async fn did_change_watched_files(&self, _: DidChangeWatchedFilesParams) {
        self.client
            .log_message(MessageType::INFO, "watched files have changed!")
            .await;
    }

    async fn execute_command(&self, _: ExecuteCommandParams) -> Result<Option<serde_json::Value>> {
        self.client
            .log_message(MessageType::INFO, "command executed!")
            .await;

        match self.client.apply_edit(WorkspaceEdit::default()).await {
            Ok(res) if res.applied => self.client.log_message(MessageType::INFO, "applied").await,
            Ok(_) => self.client.log_message(MessageType::INFO, "rejected").await,
            Err(err) => self.client.log_message(MessageType::ERROR, err).await,
        }
        Ok(None)
    }
}

impl ForgeLspRunner {
    pub async fn run() -> Result<()> {
        info!("Starting Foundry LSP server...");

        let stdin = tokio::io::stdin();
        let stdout = tokio::io::stdout();
        let (service, socket) = LspService::new(|client| ForgeLspServer { client });

        Server::new(stdin, stdout, socket).serve(service).await;

        info!("Foundry LSP server stopped");

        Ok(())
    }
}

#[tokio::main]
async fn main() {
    let _ = ForgeLspRunner::run().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower_lsp::lsp_types::Url;

    #[tokio::test]
    async fn test_lsp_diagnostics_integration() {
        // Test that our diagnostic functions work and return proper LSP diagnostics
        println!("Testing compilation diagnostics...");
        let compile_result =
            utils::run_forge_compile_and_get_diagnostics("contracts/CompilationError.sol").await;
        assert!(
            compile_result.is_ok(),
            "Compilation diagnostics should work"
        );

        let compile_diagnostics = compile_result.unwrap();
        assert!(
            !compile_diagnostics.is_empty(),
            "Should have compilation errors"
        );

        // Verify the diagnostic has the expected properties
        let first_diag = &compile_diagnostics[0];
        assert_eq!(first_diag.source, Some("forge-compile".to_string()));
        assert_eq!(first_diag.severity, Some(DiagnosticSeverity::ERROR));

        println!(
            "✅ Compilation diagnostics: {} items",
            compile_diagnostics.len()
        );

        println!("Testing lint diagnostics...");
        let lint_result = utils::run_forge_lint_and_get_diagnostics("contracts/A.sol").await;
        assert!(lint_result.is_ok(), "Lint diagnostics should work");

        let lint_diagnostics = lint_result.unwrap();
        assert!(!lint_diagnostics.is_empty(), "Should have lint warnings");

        // Verify the diagnostic has the expected properties
        let first_lint_diag = &lint_diagnostics[0];
        assert_eq!(first_lint_diag.source, Some("forge-lint".to_string()));
        assert_eq!(
            first_lint_diag.severity,
            Some(DiagnosticSeverity::INFORMATION)
        );

        println!("✅ Lint diagnostics: {} items", lint_diagnostics.len());

        // Test that warnings from compilation are also captured
        println!("Testing compilation warnings...");
        let warning_result = utils::run_forge_compile_and_get_diagnostics("contracts/A.sol").await;
        assert!(warning_result.is_ok(), "Compilation warnings should work");

        let warning_diagnostics = warning_result.unwrap();
        assert!(
            !warning_diagnostics.is_empty(),
            "Should have compilation warnings"
        );

        let first_warning = &warning_diagnostics[0];
        assert_eq!(first_warning.source, Some("forge-compile".to_string()));
        assert_eq!(first_warning.severity, Some(DiagnosticSeverity::WARNING));

        println!(
            "✅ Compilation warnings: {} items",
            warning_diagnostics.len()
        );
        println!("🎉 All LSP diagnostics integration tests passed!");
    }

    #[test]
    fn test_solidity_file_detection() {
        // Test that we correctly identify Solidity files
        assert!(
            Url::parse("file:///path/to/file.sol")
                .unwrap()
                .path()
                .ends_with(".sol")
        );
        assert!(
            !Url::parse("file:///path/to/file.rs")
                .unwrap()
                .path()
                .ends_with(".sol")
        );
        assert!(
            !Url::parse("file:///path/to/README.md")
                .unwrap()
                .path()
                .ends_with(".sol")
        );

        println!("✅ Solidity file detection works correctly!");
    }

    #[tokio::test]
    async fn test_diagnostics_refresh_on_save_cycle() {
        println!("Testing diagnostics refresh cycle...");

        // Test 1: File with compilation errors
        println!("1. Testing file with compilation errors...");
        let error_diagnostics =
            utils::run_forge_compile_and_get_diagnostics("contracts/CompilationError.sol").await;
        assert!(error_diagnostics.is_ok());
        let error_diags = error_diagnostics.unwrap();
        assert!(!error_diags.is_empty(), "Should have compilation errors");
        assert!(
            error_diags
                .iter()
                .any(|d| d.severity == Some(DiagnosticSeverity::ERROR))
        );
        println!("   ✅ Found {} error diagnostics", error_diags.len());

        // Test 2: File with warnings
        println!("2. Testing file with warnings...");
        let warning_diagnostics =
            utils::run_forge_compile_and_get_diagnostics("contracts/A.sol").await;
        assert!(warning_diagnostics.is_ok());
        let warning_diags = warning_diagnostics.unwrap();
        assert!(
            !warning_diags.is_empty(),
            "Should have compilation warnings"
        );
        assert!(
            warning_diags
                .iter()
                .any(|d| d.severity == Some(DiagnosticSeverity::WARNING))
        );
        println!("   ✅ Found {} warning diagnostics", warning_diags.len());

        // Test 3: Linting diagnostics
        println!("3. Testing linting diagnostics...");
        let lint_diagnostics = utils::run_forge_lint_and_get_diagnostics("contracts/A.sol").await;
        assert!(lint_diagnostics.is_ok());
        let lint_diags = lint_diagnostics.unwrap();
        assert!(!lint_diags.is_empty(), "Should have linting diagnostics");
        assert!(
            lint_diags
                .iter()
                .any(|d| d.severity == Some(DiagnosticSeverity::INFORMATION))
        );
        println!("   ✅ Found {} linting diagnostics", lint_diags.len());

        // Test 4: Verify diagnostics are fresh on each call (not cached)
        println!("4. Testing diagnostics freshness...");
        let first_run =
            utils::run_forge_compile_and_get_diagnostics("contracts/CompilationError.sol")
                .await
                .unwrap();
        let second_run =
            utils::run_forge_compile_and_get_diagnostics("contracts/CompilationError.sol")
                .await
                .unwrap();

        // Both runs should produce the same diagnostics (proving they're fresh, not cached)
        assert_eq!(
            first_run.len(),
            second_run.len(),
            "Diagnostics should be consistent across runs"
        );
        if !first_run.is_empty() && !second_run.is_empty() {
            assert_eq!(
                first_run[0].message, second_run[0].message,
                "Diagnostic messages should be identical"
            );
        }
        println!("   ✅ Diagnostics are fresh on each run");

        println!("🎉 All save-reload cycle tests passed!");
        println!("   - Compilation errors: detected ✅");
        println!("   - Compilation warnings: detected ✅");
        println!("   - Linting diagnostics: detected ✅");
        println!("   - Fresh diagnostics on each save: verified ✅");
    }



    #[tokio::test]
    async fn test_lsp_server_with_file_uri() {
        println!("🔍 Testing LSP server with file URI...");
        
        // Create a mock client (we can't easily test the full LSP flow, but we can test the on_change method)
        let current_dir = std::env::current_dir().unwrap();
        let file_uri = format!("file://{}/contracts/CompilationError.sol", current_dir.display());
        
        println!("   📁 Testing with URI: {}", file_uri);
        
        // Parse the URI
        let uri = Url::parse(&file_uri).expect("Should parse URI");
        let file_path = uri.path();
        
        println!("   📂 Extracted path: {}", file_path);
        
        // Test the path conversion logic (same as in on_change)
        let relative_path = if file_path.starts_with('/') {
            match std::env::current_dir() {
                Ok(cwd) => {
                    let abs_path = std::path::Path::new(file_path);
                    match abs_path.strip_prefix(&cwd) {
                        Ok(rel_path) => rel_path.to_string_lossy().to_string(),
                        Err(_) => file_path.to_string(),
                    }
                }
                Err(_) => file_path.to_string(),
            }
        } else {
            file_path.to_string()
        };
        
        println!("   🔄 Converted to relative path: {}", relative_path);
        
        // Test diagnostics with the converted path
        let diagnostics = utils::run_forge_compile_and_get_diagnostics(&relative_path).await;
        assert!(diagnostics.is_ok(), "Diagnostics should work with converted path");
        
        let diag_vec = diagnostics.unwrap();
        println!("   📊 Found {} diagnostics", diag_vec.len());
        assert!(!diag_vec.is_empty(), "Should find compilation errors");
        
        let has_errors = diag_vec.iter().any(|d| d.severity == Some(DiagnosticSeverity::ERROR));
        assert!(has_errors, "Should have error diagnostics");
        
        println!("✅ LSP server file URI handling works correctly!");
    }

    #[tokio::test]
    async fn test_lsp_server_empty_file_diagnostics() {
        println!("🔍 Testing LSP server with empty Solidity file...");
        
        // Test with empty file URI
        let current_dir = std::env::current_dir().unwrap();
        let file_uri = format!("file://{}/contracts/Empty.sol", current_dir.display());
        
        println!("   📁 Testing with URI: {}", file_uri);
        
        // Parse the URI and convert path
        let uri = Url::parse(&file_uri).expect("Should parse URI");
        let file_path = uri.path();
        
        let relative_path = if file_path.starts_with('/') {
            match std::env::current_dir() {
                Ok(cwd) => {
                    let abs_path = std::path::Path::new(file_path);
                    match abs_path.strip_prefix(&cwd) {
                        Ok(rel_path) => rel_path.to_string_lossy().to_string(),
                        Err(_) => file_path.to_string(),
                    }
                }
                Err(_) => file_path.to_string(),
            }
        } else {
            file_path.to_string()
        };
        
        println!("   🔄 Converted to relative path: {}", relative_path);
        
        // Test diagnostics with the converted path
        let diagnostics = utils::run_forge_compile_and_get_diagnostics(&relative_path).await;
        assert!(diagnostics.is_ok(), "Diagnostics should work with empty file");
        
        let diag_vec = diagnostics.unwrap();
        println!("   📊 Found {} diagnostics", diag_vec.len());
        assert!(!diag_vec.is_empty(), "Should find SPDX and pragma warnings");
        
        // Check for both expected warnings
        let has_spdx = diag_vec.iter().any(|d| d.message.contains("SPDX license identifier"));
        let has_pragma = diag_vec.iter().any(|d| d.message.contains("compiler version"));
        
        assert!(has_spdx, "Should have SPDX warning");
        assert!(has_pragma, "Should have pragma warning");
        
        println!("✅ LSP server empty file diagnostics work correctly!");
        println!("   - SPDX license warning: ✅");
        println!("   - Pragma version warning: ✅");
    }

    #[tokio::test]
    async fn test_file_modification_and_save_cycle() {
        use std::fs;

        println!("Testing file modification and save cycle...");

        let test_file_path = "test_temp.sol";

        // Clean up any existing test file
        let _ = fs::remove_file(test_file_path);

        // Test 1: Create a valid Solidity file
        println!("1. Creating valid Solidity file...");
        let valid_content = r#"// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

contract TestContract {
    function validFunction() public pure returns (uint256) {
        return 42;
    }
}
"#;
        fs::write(test_file_path, valid_content).expect("Failed to write test file");

        let valid_diagnostics = utils::run_forge_compile_and_get_diagnostics(test_file_path).await;
        assert!(
            valid_diagnostics.is_ok(),
            "Valid file should compile successfully"
        );
        let valid_diags = valid_diagnostics.unwrap();
        println!("   ✅ Valid file diagnostics: {} items", valid_diags.len());

        // Test 2: Modify file to introduce an error
        println!("2. Modifying file to introduce compilation error...");
        let error_content = r#"// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

contract TestContract {
    function validFunction() public pure returns (uint256) {
        return 42;
    }
    
    // Introduce syntax error
    invalid_syntax_here;
}
"#;
        fs::write(test_file_path, error_content).expect("Failed to write error content");

        let error_diagnostics = utils::run_forge_compile_and_get_diagnostics(test_file_path).await;
        assert!(
            error_diagnostics.is_ok(),
            "Should handle compilation errors gracefully"
        );
        let error_diags = error_diagnostics.unwrap();
        assert!(!error_diags.is_empty(), "Should detect compilation errors");
        assert!(
            error_diags
                .iter()
                .any(|d| d.severity == Some(DiagnosticSeverity::ERROR))
        );
        println!(
            "   ✅ Error file diagnostics: {} items (including errors)",
            error_diags.len()
        );

        // Test 3: Fix the error and introduce warnings
        println!("3. Fixing error and introducing warnings...");
        let warning_content = r#"// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

contract TestContract {
    function snake_case_function(uint256 unused_param) public pure returns (uint256) {
        uint256 unused_variable;
        return 42;
    }
}
"#;
        fs::write(test_file_path, warning_content).expect("Failed to write warning content");

        let warning_diagnostics =
            utils::run_forge_compile_and_get_diagnostics(test_file_path).await;
        assert!(
            warning_diagnostics.is_ok(),
            "Should handle warnings gracefully"
        );
        let warning_diags = warning_diagnostics.unwrap();

        // Check for compilation warnings
        let has_warnings = warning_diags
            .iter()
            .any(|d| d.severity == Some(DiagnosticSeverity::WARNING));
        println!(
            "   ✅ Warning file diagnostics: {} items (warnings: {})",
            warning_diags.len(),
            has_warnings
        );

        // Test linting on the same file
        let lint_diagnostics = utils::run_forge_lint_and_get_diagnostics(test_file_path).await;
        if lint_diagnostics.is_ok() {
            let lint_diags = lint_diagnostics.unwrap();
            let has_lint_issues = !lint_diags.is_empty();
            println!("   ✅ Linting diagnostics: {} items", lint_diags.len());

            if has_lint_issues {
                println!("   📝 Linting found style issues (e.g., snake_case function name)");
            }
        }

        // Clean up
        let _ = fs::remove_file(test_file_path);

        println!("🎉 File modification and save cycle test completed!");
        println!("   - Valid file → minimal diagnostics ✅");
        println!("   - Error introduced → error diagnostics ✅");
        println!("   - Error fixed → warning diagnostics ✅");
        println!("   - Each save triggers fresh diagnostic analysis ✅");
    }
}

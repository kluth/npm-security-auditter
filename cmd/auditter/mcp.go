package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/kluth/npm-security-auditter/internal/audit"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
)

func newMcpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Start the Model Context Protocol (MCP) server",
		Long: `Starts a JSON-RPC server implementing the Model Context Protocol (MCP).
This allows AI assistants (like Claude Desktop) to use Auditter as a tool.`,
		RunE: runMcpServer,
	}
}

func runMcpServer(cmd *cobra.Command, args []string) error {
	s := server.NewMCPServer(
		"npm-security-auditter",
		version,
		server.WithLogging(),
	)

	// Tool: audit-package
	auditPackageTool := mcp.NewTool("audit_package",
		mcp.WithDescription("Audit a specific npm package for security risks"),
		mcp.WithString("package_name",
			mcp.Description("The name of the npm package (e.g., 'express', 'lodash@4.17.21')"),
			mcp.Required(),
		),
	)
	s.AddTool(auditPackageTool, handleAuditPackage)

	// Tool: audit-project
	auditProjectTool := mcp.NewTool("audit_project",
		mcp.WithDescription("Audit a local project directory (package.json/package-lock.json)"),
		mcp.WithString("path",
			mcp.Description("Absolute path to the project directory or lockfile"),
			mcp.Required(),
		),
	)
	s.AddTool(auditProjectTool, handleAuditProject)

	// Tool: list-analyzers
	listAnalyzersTool := mcp.NewTool("list_analyzers",
		mcp.WithDescription("List all available security analyzers"),
	)
	s.AddTool(listAnalyzersTool, handleListAnalyzers)

	// Start server over Stdio
	// Note: We might want to handle signals gracefully, but for stdio it's usually fine.
	if err := server.ServeStdio(s); err != nil {
		return fmt.Errorf("MCP server error: %w", err)
	}

	return nil
}

func handleAuditPackage(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args, ok := request.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("arguments must be a map"), nil
	}
	pkgName, ok := args["package_name"].(string)
	if !ok {
		return mcp.NewToolResultError("package_name must be a string"), nil
	}

	// Use default config, but ensure json format for machine consumption
	cfg := audit.Config{
		RegistryURL: registryURL, // Use global flag if set, or default
		Timeout:     timeout,
		Concurrency: concurrency,
		MinSeverity: 0, // Return all, let LLM filter? Or use global flag? Let's use 0 for max info.
		NoSandbox:   noSandbox,
		Verbose:     false,
	}
	runner := audit.NewRunner(cfg)

	report, err := runner.Run(ctx, pkgName)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Audit failed: %v", err)), nil
	}

	jsonBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to marshal report: %v", err)), nil
	}

	return mcp.NewToolResultText(string(jsonBytes)), nil
}

func handleAuditProject(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args, ok := request.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("arguments must be a map"), nil
	}
	path, ok := args["path"].(string)
	if !ok {
		return mcp.NewToolResultError("path must be a string"), nil
	}

	cfg := audit.Config{
		RegistryURL: registryURL,
		Timeout:     timeout,
		Concurrency: concurrency,
		MinSeverity: 0,
		NoSandbox:   noSandbox,
		ProjectPath: path, // Set project path specifically
		Verbose:     false,
	}
	runner := audit.NewRunner(cfg)

	// The runner logic for project path might need path to be explicitly passed to Run if config sets it?
	// The current runner.Run logic uses cfg.ProjectPath if set.
	// But let's pass path to Run just in case runner logic expects it or config setup.
	// Actually runner.Run(ctx, path) handles package name OR path if it detects files.
	// But let's ensure config has it set correctly.
	
	report, err := runner.Run(ctx, path)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Audit failed: %v", err)), nil
	}

	// Truncate large reports? Project audits can be huge.
	// Maybe summarize or limit depth?
	// For now, return full JSON. The LLM context window is the limit.
	jsonBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to marshal report: %v", err)), nil
	}

	return mcp.NewToolResultText(string(jsonBytes)), nil
}

func handleListAnalyzers(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// We can't capture stdout easily from PrintAnalyzerList without a pipe.
	// Let's create a temporary pipe or modify PrintAnalyzerList to return string?
	// Or just reimplement the list generation here since we can access analyzerRegistry in audit package if we export it?
	// audit.PrintAnalyzerList writes to an io.Writer.
	
	// Create a pipe
	r, w, _ := os.Pipe()
	
	go func() {
		audit.PrintAnalyzerList(w)
		w.Close()
	}()
	
	output, _ := io.ReadAll(r)
	return mcp.NewToolResultText(string(output)), nil
}

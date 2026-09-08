package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/reconmaster/backend/internal/models"
)

// CustomScriptRunner Custom Script Runner
type CustomScriptRunner struct{}

// NewCustomScriptRunner Create a custom script operator
func NewCustomScriptRunner() *CustomScriptRunner {
	return &CustomScriptRunner{}
}

// ScriptResult Script execution results
type ScriptResult struct {
	Vulnerabilities []VulnResult `json:"vulnerabilities"`
	Message         string       `json:"message"`
	Error           string       `json:"error"`
}

// VulnResult Leak result
type VulnResult struct {
	URL         string `json:"url"`
	VulnType    string `json:"vuln_type"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Payload     string `json:"payload"`
	Proof       string `json:"proof"`
}

// RunScript Run Script
func (csr *CustomScriptRunner) RunScript(ctx *ScanContext, scriptPath string, targets []string) ([]*models.Vulnerability, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	ctx.Logger.Printf("Running custom script: %s on %d targets", scriptPath, len(targets))

	// Check for script file exists
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("script file not found: %s", scriptPath)
	}

	// Determine how to execute it by file extension
	ext := strings.ToLower(filepath.Ext(scriptPath))

	var vulnerabilities []*models.Vulnerability
	var err error

	switch ext {
	case ".py":
		vulnerabilities, err = csr.runPythonScript(ctx, scriptPath, targets)
	case ".go":
		vulnerabilities, err = csr.runGoScript(ctx, scriptPath, targets)
	case ".sh":
		vulnerabilities, err = csr.runShellScript(ctx, scriptPath, targets)
	default:
		return nil, fmt.Errorf("unsupported script type: %s", ext)
	}

	if err != nil {
		return nil, err
	}

	ctx.Logger.Printf("Custom script completed, found %d vulnerabilities", len(vulnerabilities))
	return vulnerabilities, nil
}

// runPythonScript RunPythonScript
func (csr *CustomScriptRunner) runPythonScript(ctx *ScanContext, scriptPath string, targets []string) ([]*models.Vulnerability, error) {
	// Create TemporaryJSONDocument transfer target
	tmpFile, err := os.CreateTemp("", "script-targets-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	targetsJSON, _ := json.Marshal(map[string]interface{}{
		"targets": targets,
		"task_id": ctx.Task.ID,
	})
	tmpFile.Write(targetsJSON)
	tmpFile.Close()

	// ImplementationPythonScript
	cmd := exec.Command("python3", scriptPath, tmpFile.Name())

	// Set Timeout
	cmdCtx, cancel := context.WithTimeout(ctx.Ctx, 30*time.Minute)
	defer cancel()
	cmd = exec.CommandContext(cmdCtx, "python3", scriptPath, tmpFile.Name())

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("script execution failed: %w, output: %s", err, string(output))
	}

	// Parsing Results
	return csr.parseScriptOutput(ctx, output)
}

// runGoScript RunGoScript
func (csr *CustomScriptRunner) runGoScript(ctx *ScanContext, scriptPath string, targets []string) ([]*models.Vulnerability, error) {
	// GoScripts need to be compiled first.
	scriptDir := filepath.Dir(scriptPath)
	binaryPath := filepath.Join(os.TempDir(), "custom-script-"+filepath.Base(scriptPath)+".bin")
	defer os.Remove(binaryPath)

	// Compile
	ctx.Logger.Printf("Compiling Go script: %s", scriptPath)
	compileCmd := exec.Command("go", "build", "-o", binaryPath, scriptPath)
	compileCmd.Dir = scriptDir
	if output, err := compileCmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("script compilation failed: %w, output: %s", err, string(output))
	}

	// Create TemporaryJSONDocument transfer target
	tmpFile, err := os.CreateTemp("", "script-targets-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	targetsJSON, _ := json.Marshal(map[string]interface{}{
		"targets": targets,
		"task_id": ctx.Task.ID,
	})
	tmpFile.Write(targetsJSON)
	tmpFile.Close()

	// Performed binary compilation
	cmdCtx, cancel := context.WithTimeout(ctx.Ctx, 30*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, binaryPath, tmpFile.Name())

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("script execution failed: %w, output: %s", err, string(output))
	}

	// Parsing Results
	return csr.parseScriptOutput(ctx, output)
}

// runShellScript RunShellScript
func (csr *CustomScriptRunner) runShellScript(ctx *ScanContext, scriptPath string, targets []string) ([]*models.Vulnerability, error) {
	// Transfer of the target as a parameter
	args := append([]string{scriptPath}, targets...)

	cmdCtx, cancel := context.WithTimeout(ctx.Ctx, 30*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, "bash", args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("script execution failed: %w, output: %s", err, string(output))
	}

	// Parsing Results
	return csr.parseScriptOutput(ctx, output)
}

// parseScriptOutput Parsing Script Output
func (csr *CustomScriptRunner) parseScriptOutput(ctx *ScanContext, output []byte) ([]*models.Vulnerability, error) {
	// Expecting Script OutputJSONResults of Formatting
	var result ScriptResult
	if err := json.Unmarshal(output, &result); err != nil {
		// If the parse fails, Try to parse by line
		return csr.parseLineByLine(ctx, output)
	}

	// Check for errors
	if result.Error != "" {
		return nil, fmt.Errorf("script error: %s", result.Error)
	}

	// Convert to Fault Model
	var vulnerabilities []*models.Vulnerability
	for _, vulnResult := range result.Vulnerabilities {
		vuln := &models.Vulnerability{
			TaskID:      ctx.Task.ID,
			URL:         vulnResult.URL,
			VulnType:    vulnResult.VulnType,
			Severity:    vulnResult.Severity,
			Title:       vulnResult.Title,
			Description: vulnResult.Description,
			Payload:     vulnResult.Payload,
			Proof:       vulnResult.Proof,
			Source:      "custom_script",
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	return vulnerabilities, nil
}

// parseLineByLine Page output (One in every row.JSONLeaks)
func (csr *CustomScriptRunner) parseLineByLine(ctx *ScanContext, output []byte) ([]*models.Vulnerability, error) {
	lines := strings.Split(string(output), "\n")
	var vulnerabilities []*models.Vulnerability

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var vulnResult VulnResult
		if err := json.Unmarshal([]byte(line), &vulnResult); err != nil {
			// Skipping FavourJSONOkay.
			ctx.Logger.Printf("Skipping non-JSON line: %s", line)
			continue
		}

		vuln := &models.Vulnerability{
			TaskID:      ctx.Task.ID,
			URL:         vulnResult.URL,
			VulnType:    vulnResult.VulnType,
			Severity:    vulnResult.Severity,
			Title:       vulnResult.Title,
			Description: vulnResult.Description,
			Payload:     vulnResult.Payload,
			Proof:       vulnResult.Proof,
			Source:      "custom_script",
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	return vulnerabilities, nil
}

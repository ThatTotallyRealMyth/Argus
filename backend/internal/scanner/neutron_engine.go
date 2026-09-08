package scanner

import (
	"fmt"
	"log"

	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/templates"
	"github.com/reconmaster/backend/internal/models"
	"gopkg.in/yaml.v3"
)

// NeutronEngine NeutronEngine packaging
type NeutronEngine struct {
	options *protocols.ExecuterOptions
}

// NewNeutronEngine CreateNeutronEngine
func NewNeutronEngine() *NeutronEngine {
	return &NeutronEngine{
		options: &protocols.ExecuterOptions{
			Options: &protocols.Options{
				Timeout: 30,
			},
		},
	}
}

// NeutronResult NeutronResults of implementation
type NeutronResult struct {
	Vulnerable    bool
	TemplateID    string
	MatcherName   string
	ExtractedData []string
	Message       string
	Details       string
}

// ExecutePoC UseNeutronImplementationPoC
func (ne *NeutronEngine) ExecutePoC(poc *models.PoC, target string) (*NeutronResult, error) {
	// Parsing PoC Templates
	tmpl := &templates.Template{}
	if err := yaml.Unmarshal([]byte(poc.PoCContent), tmpl); err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	// Compile Template
	if err := tmpl.Compile(ne.options); err != nil {
		return nil, fmt.Errorf("failed to compile template: %w", err)
	}

	// Execute Template
	result, err := tmpl.Execute(target, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to execute template: %w", err)
	}

	// Convert Results
	neutronResult := &NeutronResult{
		Vulnerable: result.Matched,
		TemplateID: tmpl.Id,
		Message:    "No vulnerabilities detected",
	}

	if result.Matched {
		// Name of the rule to collect matching
		var matcherNames []string
		for matcherName := range result.Matches {
			matcherNames = append(matcherNames, matcherName)
		}
		if len(matcherNames) > 0 {
			neutronResult.MatcherName = matcherNames[0]
		}

		// Collection of extracted data
		var extracted []string
		for _, values := range result.Extracts {
			extracted = append(extracted, values...)
		}
		neutronResult.ExtractedData = extracted

		neutronResult.Message = fmt.Sprintf("Vulnerability detected: %s", neutronResult.MatcherName)
		neutronResult.Details = fmt.Sprintf("Template: %s, Matched: %v", tmpl.Id, matcherNames)
	}

	return neutronResult, nil
}

// ExecutePoCBatch Batch executionPoC
func (ne *NeutronEngine) ExecutePoCBatch(pocs []*models.PoC, targets []string) (map[string][]*NeutronResult, error) {
	results := make(map[string][]*NeutronResult)

	// Parsing all templates
	var tmpls []*templates.Template
	for _, poc := range pocs {
		tmpl := &templates.Template{}
		if err := yaml.Unmarshal([]byte(poc.PoCContent), tmpl); err != nil {
			log.Printf("Warning: Failed to parse template %s: %v", poc.Name, err)
			continue
		}

		if err := tmpl.Compile(ne.options); err != nil {
			log.Printf("Warning: Failed to compile template %s: %v", poc.Name, err)
			continue
		}

		tmpls = append(tmpls, tmpl)
	}

	if len(tmpls) == 0 {
		return results, fmt.Errorf("no valid templates to execute")
	}

	// Execute all templates for each target
	for _, target := range targets {
		for _, tmpl := range tmpls {
			result, err := tmpl.Execute(target, nil)
			if err != nil {
				log.Printf("Warning: Failed to execute template %s on %s: %v", tmpl.Id, target, err)
				continue
			}

			neutronResult := &NeutronResult{
				Vulnerable: result.Matched,
				TemplateID: tmpl.Id,
				Message:    "No vulnerabilities detected",
			}

			if result.Matched {
				var matcherNames []string
				for matcherName := range result.Matches {
					matcherNames = append(matcherNames, matcherName)
				}
				if len(matcherNames) > 0 {
					neutronResult.MatcherName = matcherNames[0]
				}

				var extracted []string
				for _, values := range result.Extracts {
					extracted = append(extracted, values...)
				}
				neutronResult.ExtractedData = extracted

				neutronResult.Message = fmt.Sprintf("Vulnerability detected: %s", neutronResult.MatcherName)
				neutronResult.Details = fmt.Sprintf("Template: %s, Matched: %v", tmpl.Id, matcherNames)
			}

			results[target] = append(results[target], neutronResult)
		}
	}

	return results, nil
}

// SetTimeout Set timeout
func (ne *NeutronEngine) SetTimeout(timeout int) {
	ne.options.Options.Timeout = timeout
}

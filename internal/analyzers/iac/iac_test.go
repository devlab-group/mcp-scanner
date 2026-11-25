package iac

import (
	"context"
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/testutil"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

func run(t *testing.T, files map[string]string) model.AnalyzerResult {
	t.Helper()
	dir := testutil.WriteTree(t, files)
	ac := &analyzer.AnalysisContext{Root: dir, Artifacts: analyzer.NewArtifacts()}
	res := (&Analyzer{}).Analyze(context.Background(), model.Target{Kind: model.TargetSource, Path: dir}, ac)
	for _, f := range res.Findings {
		if err := f.Validate(); err != nil {
			t.Fatalf("invalid finding %s: %v", f.RuleID, err)
		}
	}
	return res
}

func one(t *testing.T, res model.AnalyzerResult, rule string, sev model.Severity, triage model.Triage) model.Finding {
	t.Helper()
	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("status = %s", res.Status)
	}
	if len(res.Findings) != 1 || res.Findings[0].RuleID != rule {
		t.Fatalf("want one %s, got %+v", rule, res.Findings)
	}
	f := res.Findings[0]
	if f.Severity != sev || f.Triage != triage {
		t.Fatalf("severity/triage = %s/%s, want %s/%s: %s", f.Severity, f.Triage, sev, triage, f.Description)
	}
	return f
}

func none(t *testing.T, res model.AnalyzerResult) {
	t.Helper()
	for _, f := range res.Findings {
		t.Errorf("unexpected %s at %s:%d: %s", f.RuleID, f.File, f.Line, f.Description)
	}
}

const firewallAll = `
resource fw 'Microsoft.Sql/servers/firewallRules@2023-05-01-preview' = {
  parent: sql
  name: 'everyone'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '255.255.255.255'
  }
}
`

func sqlServer(password string) string {
	return `resource sql 'Microsoft.Sql/servers@2023-05-01-preview' = {
  name: 'sql-${uniqueString(resourceGroup().id)}'
  location: location
  properties: {
    administratorLogin: 'owner'
    administratorLoginPassword: ` + password + `
  }
}
`
}

func TestBicepLiteralBehindOpenFirewall(t *testing.T) {
	f := one(t, run(t, map[string]string{"deploy/sql.bicep": "param location string\n" + sqlServer("'Owner-Pass-77'") + firewallAll}),
		RuleHardcodedSecret, model.SeverityHigh, model.TriagePotential)
	if strings.Contains(f.Description, "Owner-Pass-77") {
		t.Fatalf("the secret itself must not be printed: %s", f.Description)
	}
	if f.File != "deploy/sql.bicep" || f.Line != 7 {
		t.Fatalf("location %s:%d", f.File, f.Line)
	}
}

func TestBicepSecureParamDefaultIsHardcoded(t *testing.T) {
	f := one(t, run(t, map[string]string{"main.bicep": "param location string\n@secure()\nparam ownerPassword string = 'letmein-2025'\n" + sqlServer("ownerPassword")}),
		RuleHardcodedSecret, model.SeverityMedium, model.TriageNeedsReview)
	if !strings.Contains(f.Description, "default of parameter ownerPassword") {
		t.Fatalf("description should name the default: %s", f.Description)
	}
}

func TestBicepDefaultOverriddenByParametersFile(t *testing.T) {
	none(t, run(t, map[string]string{
		"main.bicep": "param location string\n@secure()\nparam ownerPassword string = 'letmein-2025'\n" + sqlServer("ownerPassword") + firewallAll,
		"main.parameters.json": `{"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
 "contentVersion": "1.0.0.0", "parameters": {"ownerPassword": {"value": "${AZURE_SQL_PASSWORD}"}}}`,
	}))
}

func TestBicepHashOfNameTokenIsPredictable(t *testing.T) {
	src := "param env string\nparam location string\nvar tag = uniqueString(subscription().id, env)\nvar pw = '${uniqueString(tag)}Aa1!'\n" +
		"resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {\n  name: 'kv-${tag}'\n}\n" + sqlServer("pw") + firewallAll
	f := one(t, run(t, map[string]string{"infra/main.bicep": src}), RulePredictableSecret, model.SeverityHigh, model.TriagePotential)
	if !strings.Contains(f.Description, "tag") {
		t.Fatalf("description should name the public input: %s", f.Description)
	}
}

func TestBicepHashOfPrivateValuesGoesToReview(t *testing.T) {
	src := "param location string\nvar pw = 'P${uniqueString(resourceGroup().id, 'pw')}'\n" + sqlServer("pw") + firewallAll
	one(t, run(t, map[string]string{"main.bicep": src}), RulePredictableSecret, model.SeverityMedium, model.TriageNeedsReview)
}

func TestBicepGeneratedAndVaultSecretsAreFine(t *testing.T) {
	none(t, run(t, map[string]string{
		"a.bicep": "param location string\n@secure()\nparam p string = newGuid()\n" + sqlServer("p") + firewallAll,
		"b.bicep": "param location string\nresource v 'Microsoft.KeyVault/vaults@2023-07-01' existing = {\n  name: 'v'\n}\nmodule m 'c.bicep' = {\n  name: 'm'\n  params: {\n    adminPassword: v.getSecret('pw')\n  }\n}\n",
		"c.bicep": "param location string = 'x'\n@secure()\nparam adminPassword string\n" + sqlServer("adminPassword"),
	}))
}

func TestTerraformLiteralOnPublicInstance(t *testing.T) {
	one(t, run(t, map[string]string{"tf/db.tf": `resource "aws_db_instance" "x" {
  username            = "app"
  password            = "app-pass-1"
  publicly_accessible = true
}
`}), RuleHardcodedSecret, model.SeverityHigh, model.TriagePotential)
}

func TestTerraformVariableDefaultAndTfvars(t *testing.T) {
	f := one(t, run(t, map[string]string{
		"vars.tf": "variable \"pg_pass\" {\n  type      = string\n  sensitive = true\n  default   = \"Default-Pg-9\"\n}\n",
		"db.tf":   "resource \"azurerm_postgresql_flexible_server\" \"x\" {\n  administrator_password = var.pg_pass\n}\n",
	}), RuleHardcodedSecret, model.SeverityMedium, model.TriageNeedsReview)
	if f.File != "db.tf" || !strings.Contains(f.Description, "default of variable pg_pass") {
		t.Fatalf("finding should be at the use and name the default: %s:%d %s", f.File, f.Line, f.Description)
	}
	res := run(t, map[string]string{
		"vars.tf":          "variable \"pg_pass\" {\n  type = string\n}\n",
		"db.tf":            "resource \"azurerm_postgresql_flexible_server\" \"x\" {\n  administrator_password = var.pg_pass\n}\n",
		"terraform.tfvars": "pg_pass = \"Committed-Pass-3\"\n",
	})
	if len(res.Findings) == 0 {
		t.Fatal("a password committed in terraform.tfvars is a fixed secret")
	}
}

func TestTerraformRandomPasswordIsFine(t *testing.T) {
	none(t, run(t, map[string]string{"main.tf": "resource \"random_password\" \"p\" {\n  length = 24\n}\nresource \"aws_db_instance\" \"x\" {\n  password = random_password.p.result\n  publicly_accessible = true\n}\n"}))
}

func TestARMSecureParameterDefault(t *testing.T) {
	src := `{"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
 "parameters": {"pw": {"type": "securestring", "defaultValue": "Arm-Default-1"}, "ok": {"type": "securestring", "defaultValue": "[newGuid()]"}},
 "resources": [
  {"type": "Microsoft.Sql/servers", "name": "a", "properties": {"administratorLoginPassword": "[parameters('pw')]"}},
  {"type": "Microsoft.Sql/servers", "name": "b", "properties": {"administratorLoginPassword": "[parameters('ok')]"}}
 ]}`
	f := one(t, run(t, map[string]string{"azuredeploy.json": src}), RuleHardcodedSecret, model.SeverityMedium, model.TriageNeedsReview)
	if f.Line != 4 {
		t.Fatalf("line = %d, want the property on line 4", f.Line)
	}
}

func TestNoTemplatesIsSkipped(t *testing.T) {
	res := run(t, map[string]string{"server.py": "print('hi')\n", "package.json": `{"name":"x"}`})
	if res.Status != model.AnalyzerSkipped {
		t.Fatalf("status = %s, want SKIPPED for a tree without templates", res.Status)
	}
}

func TestTestFixturesAreNotRead(t *testing.T) {
	res := run(t, map[string]string{
		"test-fixtures/security/bad.tf": "resource \"aws_db_instance\" \"x\" {\n  password = \"fixture-pass\"\n}\n",
		"main.tf":                       "resource \"random_password\" \"p\" {\n  length = 20\n}\n",
	})
	none(t, res)
	if res.Coverage.FilesParsed != 1 {
		t.Fatalf("files parsed = %d, want only main.tf", res.Coverage.FilesParsed)
	}
}

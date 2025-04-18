package analyzer

import (
	"fmt"
	"strings"

	"github.com/alecthomas/kingpin/v2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/airbrake"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/airtable/airtableoauth"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/airtable/airtablepat"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/anthropic"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/asana"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/bitbucket"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/digitalocean"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/dockerhub"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/elevenlabs"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/figma"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/github"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/gitlab"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/groq"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/huggingface"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/launchdarkly"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/mailchimp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/mailgun"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/mysql"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/notion"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/openai"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/opsgenie"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/plaid"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/planetscale"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/postgres"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/postman"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/privatekey"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/sendgrid"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/shopify"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/slack"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/sourcegraph"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/square"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/stripe"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/analyzers/twilio"
	"github.com/trufflesecurity/trufflehog/v3/pkg/analyzer/config"
)

type SecretInfo struct {
	Parts map[string]string
	Cfg   *config.Config
}

var (
	// TODO: Add list of supported key types.
	analyzeKeyType *string
	analyzeKey     *string

	showAll *bool
	log     *bool
)

func Command(app *kingpin.Application) *kingpin.CmdClause {
	cli := app.Command("analyze", "Analyze API keys for fine-grained permissions information.")

	showAll = cli.Flag("show-all", "Show all data, including permissions not available to this account + publicly-available data related to this account.").Default("false").Bool()
	log = cli.Flag("log", "Log all HTTP requests sent during analysis to a file").Default("false").Bool()
	keyTypeHelp := fmt.Sprintf(
		"Type of key to analyze. Omit to interactively choose. Available key types: %s",
		strings.Join(analyzers.AvailableAnalyzers(), ", "),
	)
	// Lowercase the available analyzers.
	availableAnalyzers := make([]string, len(analyzers.AvailableAnalyzers()))
	for i, a := range analyzers.AvailableAnalyzers() {
		availableAnalyzers[i] = strings.ToLower(a)
	}
	analyzeKeyType = cli.Flag("type", keyTypeHelp).Enum(availableAnalyzers...)
	analyzeKey = cli.Flag("key", "The key to analyze.").String()

	return cli
}

func Run(cmd string) {
	// Initialize configuration
	cfg := &config.Config{
		LoggingEnabled: *log,
		ShowAll:        *showAll,
	}

	key := *analyzeKey
	switch strings.ToLower(*analyzeKeyType) {
	case "github":
		github.AnalyzeAndPrintPermissions(cfg, key)
	case "sendgrid":
		sendgrid.AnalyzeAndPrintPermissions(cfg, key)
	case "openai":
		openai.AnalyzeAndPrintPermissions(cfg, key)
	case "postgres":
		postgres.AnalyzeAndPrintPermissions(cfg, key)
	case "mysql":
		mysql.AnalyzeAndPrintPermissions(cfg, key)
	case "slack":
		slack.AnalyzeAndPrintPermissions(cfg, key)
	case "twilio":
		parts := strings.SplitN(key, ":", 2)
		twilio.AnalyzeAndPrintPermissions(cfg, parts[0], parts[1])
	case "airbrake":
		airbrake.AnalyzeAndPrintPermissions(cfg, key)
	case "huggingface":
		huggingface.AnalyzeAndPrintPermissions(cfg, key)
	case "stripe":
		stripe.AnalyzeAndPrintPermissions(cfg, key)
	case "gitlab":
		gitlab.AnalyzeAndPrintPermissions(cfg, key)
	case "mailchimp":
		mailchimp.AnalyzeAndPrintPermissions(cfg, key)
	case "postman":
		postman.AnalyzeAndPrintPermissions(cfg, key)
	case "bitbucket":
		bitbucket.AnalyzeAndPrintPermissions(cfg, key)
	case "asana":
		asana.AnalyzeAndPrintPermissions(cfg, key)
	case "mailgun":
		mailgun.AnalyzeAndPrintPermissions(cfg, key)
	case "square":
		square.AnalyzeAndPrintPermissions(cfg, key)
	case "sourcegraph":
		sourcegraph.AnalyzeAndPrintPermissions(cfg, key)
	case "shopify":
		parts := strings.SplitN(key, ":", 2)
		shopify.AnalyzeAndPrintPermissions(cfg, parts[0], parts[1])
	case "opsgenie":
		opsgenie.AnalyzeAndPrintPermissions(cfg, key)
	case "privatekey":
		privatekey.AnalyzeAndPrintPermissions(cfg, key)
	case "notion":
		notion.AnalyzeAndPrintPermissions(cfg, key)
	case "dockerhub":
		parts := strings.SplitN(key, ":", 2)
		dockerhub.AnalyzeAndPrintPermissions(cfg, parts[0], parts[1])
	case "anthropic":
		anthropic.AnalyzeAndPrintPermissions(cfg, key)
	case "digitalocean":
		digitalocean.AnalyzeAndPrintPermissions(cfg, key)
	case "elevenlabs":
		elevenlabs.AnalyzeAndPrintPermissions(cfg, key)
	case "planetscale":
		parts := strings.SplitN(key, ":", 2)
		planetscale.AnalyzeAndPrintPermissions(cfg, parts[0], parts[1])
	case "airtableoauth":
		airtableoauth.AnalyzeAndPrintPermissions(cfg, key)
	case "airtablepat":
		airtablepat.AnalyzeAndPrintPermissions(cfg, key)
	case "groq":
		groq.AnalyzeAndPrintPermissions(cfg, key)
	case "launchdarkly":
		launchdarkly.AnalyzeAndPrintPermissions(cfg, key)
	case "figma":
		figma.AnalyzeAndPrintPermissions(cfg, key)
	case "plaid":
		parts := strings.SplitN(key, ":", 2)
		plaid.AnalyzeAndPrintPermissions(cfg, parts[0], parts[1], parts[3])
	}
}

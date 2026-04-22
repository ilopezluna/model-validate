package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ilopezluna/model-validate/validator"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(
	ctx context.Context,
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
) int {
	fs := flag.NewFlagSet("model-validate", flag.ContinueOnError)
	fs.SetOutput(stderr)

	output := fs.String("output", "human", "output format: human or json")
	policy := fs.String("policy", string(validator.PolicyDefault), "validation policy")
	dockerConfig := fs.String("docker-config", "", "path to Docker config.json")
	username := fs.String("username", "", "registry username")
	passwordStdin := fs.Bool("password-stdin", false, "read password from stdin")
	registryToken := fs.String("registry-token", "", "registry bearer token")
	plainHTTP := fs.Bool("plain-http", false, "use HTTP instead of HTTPS")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	remaining := fs.Args()
	if len(remaining) != 1 {
		_, _ = fmt.Fprintln(stderr, "usage: model-validate [flags] <reference>")
		return 2
	}

	password := ""
	if *passwordStdin {
		if *registryToken != "" {
			_, _ = fmt.Fprintln(stderr, "--password-stdin cannot be used with --registry-token")
			return 2
		}

		rawPassword, err := io.ReadAll(stdin)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "failed to read password from stdin: %v\n", err)
			return 2
		}
		password = strings.TrimRight(string(rawPassword), "\r\n")
	}

	if *output != "human" && *output != "json" {
		_, _ = fmt.Fprintf(stderr, "unsupported output format %q\n", *output)
		return 2
	}

	result, err := validator.ValidateReference(
		ctx,
		remaining[0],
		validator.Options{
			Policy:           validator.Policy(*policy),
			PlainHTTP:        *plainHTTP,
			DockerConfigPath: *dockerConfig,
			Username:         *username,
			Password:         password,
			RegistryToken:    *registryToken,
		},
	)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "validation failed: %v\n", err)
		return 2
	}

	if *output == "json" {
		encoder := json.NewEncoder(stdout)
		if err := encoder.Encode(result); err != nil {
			_, _ = fmt.Fprintf(stderr, "failed to write JSON output: %v\n", err)
			return 2
		}
	} else if err := writeHumanResult(stdout, result); err != nil {
		_, _ = fmt.Fprintf(stderr, "failed to write output: %v\n", err)
		return 2
	}

	if result.ErrorCount > 0 {
		return 1
	}
	return 0
}

func writeHumanResult(
	w io.Writer,
	result validator.Result,
) error {
	status := "PASS"
	switch {
	case result.ErrorCount > 0:
		status = "FAIL"
	case result.WarningCount > 0:
		status = "PASS WITH WARNINGS"
	}

	if _, err := fmt.Fprintf(w, "%s\n", status); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Reference: %s\n", result.Reference); err != nil {
		return err
	}
	if result.ResolvedDigest != "" {
		if _, err := fmt.Fprintf(w, "Resolved: %s\n", result.ResolvedDigest); err != nil {
			return err
		}
	}

	for _, finding := range result.Findings {
		line := fmt.Sprintf(
			"%s %s",
			strings.ToUpper(string(finding.Severity)),
			finding.Code,
		)
		if finding.Path != "" {
			line += " " + finding.Path
		}
		line += ": " + finding.Message
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}

	return nil
}

package cmd

import (
	"bytes"
	"testing"
)

func executeTestCommand(args []string) (string, error) {
	var out bytes.Buffer
	root := NewRootCommand()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func TestCommandsRequireOneArgument(t *testing.T) {
	for _, name := range []string{"domain", "http", "dns", "tls"} {
		for _, args := range [][]string{{name}, {name, "one", "two"}} {
			if _, err := executeTestCommand(args); err == nil {
				t.Fatalf("expected argument error for %v", args)
			}
		}
	}
}

package cmd

import (
	"io"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRootRejectsInvalidFlags(t *testing.T) {
	tests := []struct{ flag, value, message string }{
		{"--format", "yaml", "unsupported output format"},
		{"--timeout", "0", "timeout must be"},
		{"--timeout", "-1", "timeout must be"},
	}
	if strconv.IntSize == 64 {
		tests = append(tests, struct{ flag, value, message string }{"--timeout", strconv.FormatInt(math.MaxInt64, 10), "timeout must be"})
	}
	for _, tt := range tests {
		t.Run(tt.flag+tt.value, func(t *testing.T) {
			root := NewRootCommand()
			root.SetOut(io.Discard)
			root.SetErr(io.Discard)
			root.SetArgs([]string{"http", "not-a-url", tt.flag, tt.value})
			err := root.Execute()
			if err == nil || !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("expected %s, got %v", tt.message, err)
			}
		})
	}
}

func TestRootFlagsAndIsolation(t *testing.T) {
	for _, tt := range []struct {
		args    []string
		timeout int
		format  string
	}{
		{[]string{"http", "unused", "--timeout", "30", "--format", "json"}, 30, "json"},
		{[]string{"http", "unused"}, 10, "text"},
	} {
		root := NewRootCommand()
		child, _, err := root.Find([]string{"http"})
		if err != nil {
			t.Fatal(err)
		}
		child.RunE = func(cmd *cobra.Command, _ []string) error {
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				return err
			}
			format, err := cmd.Flags().GetString("format")
			if err != nil {
				return err
			}
			if timeout != tt.timeout || format != tt.format {
				t.Fatalf("incorrect inherited flags: %d %s", timeout, format)
			}
			return nil
		}
		root.SetArgs(tt.args)
		if err := root.Execute(); err != nil {
			t.Fatal(err)
		}
	}
}

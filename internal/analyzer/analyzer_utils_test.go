package analyzer

import (
	"testing"
)

func TestStripComments(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string // We expect spaces to replace content, but newlines to remain
	}{
		{
			name:     "single line comment",
			input:    "const x = 1; // this is a comment",
			expected: "const x = 1;                     ",
		},
		{
			name: "multi line comment",
			input: `const x = 1; /*
multi line
comment
*/ const y = 2;`,
			expected: `const x = 1;   
          
       
   const y = 2;`,
		},
		{
			name: "mixed comments",
			input: `// start
const x = 1; /* comment */ const y = 2; // end`,
			expected: `        
const x = 1;               const y = 2;       `,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StripComments(tt.input)
			if got != tt.expected {
				t.Errorf("StripComments() = %q, want %q", got, tt.expected)
			}
			// Verify line count
			inputLines := 0
			for _, r := range tt.input {
				if r == '\n' {
					inputLines++
				}
			}
			gotLines := 0
			for _, r := range got {
				if r == '\n' {
					gotLines++
				}
			}
			if inputLines != gotLines {
				t.Errorf("StripComments() line count = %d, want %d", gotLines, inputLines)
			}
		})
	}
}

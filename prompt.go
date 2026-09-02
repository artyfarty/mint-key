package main

import (
	"fmt"
	"os"

	"github.com/charmbracelet/huh"
	"golang.org/x/term"
)

// isInteractive returns true if stdin is a terminal.
func isInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// pushTermTitle sets the terminal window/tab title, saving the previous one on
// the terminal's title stack (xterm CSI 22;0t — honoured by xterm, VTE, iTerm2,
// kitty, Windows Terminal; silently ignored elsewhere). The returned function
// pops it back. No-op when stdout isn't a terminal, so piped output stays clean.
func pushTermTitle(title string) func() {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return func() {}
	}
	if t := os.Getenv("TERM"); t == "" || t == "dumb" {
		return func() {}
	}
	// Save, then OSC 0 (icon name + window title, the pane title under tmux).
	fmt.Fprintf(os.Stdout, "\033[22;0t\033]0;%s\a", title)
	return func() { fmt.Fprint(os.Stdout, "\033[23;0t") }
}

// promptChoice shows a select list and returns the 0-based index.
func promptChoice(label string, options []string) (int, error) {
	return promptChoiceDefault(label, options, 0)
}

// promptChoiceDefault is promptChoice with the cursor pre-placed on def.
func promptChoiceDefault(label string, options []string, def int) (int, error) {
	selected := def
	if selected < 0 || selected >= len(options) {
		selected = 0
	}
	opts := make([]huh.Option[int], len(options))
	for i, o := range options {
		opts[i] = huh.NewOption(o, i)
	}
	err := huh.NewSelect[int]().
		Title(label).
		Options(opts...).
		Value(&selected).
		Run()
	return selected, err
}

// promptString asks for text input with an optional default.
func promptString(label, defaultVal string) (string, error) {
	val := defaultVal
	input := huh.NewInput().Title(label).Value(&val)
	if defaultVal != "" {
		input = input.Placeholder(defaultVal)
	}
	if err := input.Run(); err != nil {
		return defaultVal, err
	}
	if val == "" {
		return defaultVal, nil
	}
	return val, nil
}

// promptYesNo asks a yes/no question.
func promptYesNo(label string, defaultYes bool) (bool, error) {
	val := defaultYes
	err := huh.NewConfirm().
		Title(label).
		Affirmative("Yes").
		Negative("No").
		Value(&val).
		Run()
	return val, err
}

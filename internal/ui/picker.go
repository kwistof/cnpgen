package ui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"
)

// PickerItem is one selectable row in a Picker checklist.
type PickerItem struct {
	Label    string // the line shown next to the checkbox
	SubLabel string // optional: an extra line shown dimmed, indented under Label
	Checked  bool   // initial (and, after Picker returns, final) selection state
}

// Picker shows an arrow-key, checkbox-style multi-select list on the
// terminal, with a "Select all" row above the items and a "Done" row below:
// Up/Down (or j/k) move the cursor, Space or Enter toggles the current item
// (or activates Select all / Done), Esc/q/Ctrl-C cancels. Returns the
// indices of every item left checked when Done is activated, or (nil, false)
// if cancelled.
//
// Falls back to a plain numbered-list-plus-line-input prompt when stdin/
// stdout isn't a real terminal (piped input, non-interactive CI), since raw
// mode has nothing to attach to there.
func Picker(title string, items []PickerItem) ([]int, bool) {
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		return linePicker(title, items, os.Stdin, os.Stdout)
	}
	return rawPicker(title, items)
}

// termWidth returns the terminal's column count, or 80 if it can't be read
// (e.g. a pipe pretending to be a TTY, or a very old terminal).
func termWidth() int {
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
		return w
	}
	return 80
}

// visibleWidth returns the number of runes in s that aren't part of an ANSI
// "\033[...m" color escape, i.e. what a terminal would actually render s as
// wide. Labels built with the ui color helpers (Bold, Dim, ...) carry these
// sequences, and counting their bytes as visible columns would wrap too
// early and (worse) can cut a line mid-escape, leaking color into whatever
// comes after.
func visibleWidth(s string) int {
	n := 0
	inEscape := false
	for _, r := range s {
		switch {
		case inEscape:
			if r == 'm' {
				inEscape = false
			}
		case r == '\033':
			inEscape = true
		default:
			n++
		}
	}
	return n
}

// wrapWidth splits s into chunks of at most width *visible* columns (any
// ANSI color escapes don't count against the width, and are never split
// across a wrap point), breaking on spaces where possible so words aren't
// split mid-word. Matches how a terminal itself would wrap the line, which
// is what the redraw logic needs to know to move the cursor by the right
// number of rows.
func wrapWidth(s string, width int) []string {
	if width <= 0 || visibleWidth(s) <= width {
		return []string{s}
	}
	var lines []string
	for _, s := range strings.Split(s, "\n") {
		for visibleWidth(s) > width {
			cutByte, lastSpaceByte := 0, -1
			visible := 0
			i := 0
			for i < len(s) {
				if s[i] == '\033' {
					j := strings.IndexByte(s[i:], 'm')
					if j < 0 {
						break
					}
					i += j + 1
					continue
				}
				if visible == width {
					cutByte = i
					break
				}
				if s[i] == ' ' {
					lastSpaceByte = i
				}
				visible++
				i++
			}
			if cutByte == 0 {
				cutByte = i // width >= remaining visible content
			}
			if lastSpaceByte > 0 {
				cutByte = lastSpaceByte
			}
			// A cut mid-way through colored text could leave a color code
			// "open" on this line (its \033[0m reset ends up on the next
			// line instead), which would bleed that color onto whatever the
			// terminal draws after this line. An unconditional reset here is
			// a no-op when nothing was open and a safety net when it was.
			lines = append(lines, s[:cutByte]+"\033[0m")
			s = strings.TrimLeft(s[cutByte:], " ")
		}
		lines = append(lines, s)
	}
	return lines
}

// rowKind distinguishes the two action rows from real checkbox items in the
// combined, navigable row list rawPicker renders.
type rowKind int

const (
	rowSelectAll rowKind = iota
	rowItem
	rowDone
)

func rawPicker(title string, items []PickerItem) ([]int, bool) {
	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return linePicker(title, items, os.Stdin, os.Stdout)
	}
	defer term.Restore(fd, oldState)

	checked := make([]bool, len(items))
	for i, it := range items {
		checked[i] = it.Checked
	}
	// kinds/itemIdx line up 1:1 with the rendered rows: row 0 is "Select
	// all", the next len(items) rows are the checklist, the last row is
	// "Done". itemIdx is only meaningful for rowItem rows.
	kinds := make([]rowKind, len(items)+2)
	itemIdx := make([]int, len(items)+2)
	kinds[0] = rowSelectAll
	for i := range items {
		kinds[i+1] = rowItem
		itemIdx[i+1] = i
	}
	kinds[len(items)+1] = rowDone
	cursor := 1 // start on the first real item (or Done, if there are none)
	prevRows := 0

	// gutter is "  [ ] " / "> [x] " etc: always 6 visible columns, so
	// continuation lines can be indented to line up under the label text
	// instead of under the checkbox.
	const gutterWidth = 6

	render := func() {
		width := termWidth()
		var rows []string
		for _, l := range wrapWidth(title, width) {
			rows = append(rows, Bold(l))
		}
		labelWidth := width - gutterWidth
		gutterPad := strings.Repeat(" ", gutterWidth)
		addRow := func(rowN int, box, label, sub string) {
			cursorMark := "  "
			if rowN == cursor {
				cursorMark = Cyan("> ")
			}
			// An action row (box == "") has no checkbox: its own "[ ... ]"
			// label starts right where a checklist row's "[x]"/"[ ]" does,
			// instead of leaving room for a box that isn't there.
			prefix := cursorMark + box
			if box != "" {
				prefix += " "
			}
			for j, l := range wrapWidth(label, labelWidth) {
				if j == 0 {
					rows = append(rows, prefix+l)
				} else {
					rows = append(rows, gutterPad+l)
				}
			}
			// Wrapped separately from label (and re-dimmed per physical line,
			// not as one long colored string that gets cut) so every line of
			// the sub-label is uniformly grey, not just wherever the first
			// wrap point happened to land.
			for _, l := range wrapWidth(sub, labelWidth) {
				rows = append(rows, gutterPad+Dim(l))
			}
		}

		rows = append(rows, "")
		selectAllLabel := "[ Select all ]"
		if allChecked(checked) {
			selectAllLabel = "[ Unselect all ]"
		}
		addRow(0, "", Bold(selectAllLabel), "")
		for i, it := range items {
			box := "[ ]"
			if checked[i] {
				box = Green("[x]")
			}
			addRow(i+1, box, it.Label, it.SubLabel)
		}
		addRow(len(items)+1, "", Bold(Green("[ Done ]")), "")

		// Redraw from a fixed home position (move up by exactly how many
		// physical rows the previous frame occupied, which wrapWidth also
		// computed, so this stays correct regardless of terminal width or
		// how long an item's label is).
		if prevRows > 0 {
			fmt.Fprintf(os.Stdout, "\r\033[%dA", prevRows)
		}
		fmt.Fprint(os.Stdout, "\033[J") // clear from cursor to end of screen
		for _, r := range rows {
			fmt.Fprint(os.Stdout, r+"\r\n")
		}
		prevRows = len(rows)
	}

	confirm := func() ([]int, bool) {
		var picked []int
		for i, c := range checked {
			if c {
				picked = append(picked, i)
			}
		}
		return picked, true
	}

	activate := func() (result []int, done bool, exit bool) {
		switch kinds[cursor] {
		case rowSelectAll:
			want := !allChecked(checked) // toggle: select all, or unselect all if already all checked
			for i := range checked {
				checked[i] = want
			}
		case rowItem:
			i := itemIdx[cursor]
			checked[i] = !checked[i]
		case rowDone:
			r, ok := confirm()
			return r, ok, true
		}
		return nil, false, false
	}

	reader := bufio.NewReader(os.Stdin)
	render()
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return nil, false
		}
		switch b {
		case 3, 'q', 27: // Ctrl-C, q, or Esc (also the start of an arrow sequence)
			if b == 27 {
				// Might be an arrow key (ESC [ A/B); peek the next two bytes.
				if next, err := reader.Peek(2); err == nil && len(next) == 2 && next[0] == '[' {
					reader.Discard(2)
					switch next[1] {
					case 'A': // up
						cursor = clampCursor(cursor-1, len(kinds))
					case 'B': // down
						cursor = clampCursor(cursor+1, len(kinds))
					}
					render()
					continue
				}
			}
			return nil, false
		case 'k':
			cursor = clampCursor(cursor-1, len(kinds))
			render()
		case 'j':
			cursor = clampCursor(cursor+1, len(kinds))
			render()
		case ' ', '\r', '\n':
			if result, done, exit := activate(); exit {
				return result, done
			}
			render()
		}
	}
}

func clampCursor(c, n int) int { return ((c % n) + n) % n }

// allChecked reports whether every item is checked (false for an empty list,
// so "Select all" still reads as select rather than unselect when there's
// nothing to check).
func allChecked(checked []bool) bool {
	if len(checked) == 0 {
		return false
	}
	for _, c := range checked {
		if !c {
			return false
		}
	}
	return true
}

// linePicker is the non-interactive fallback: a numbered list, one line of
// comma-separated indices (or "all"/blank) read with a plain Scanner.
func linePicker(title string, items []PickerItem, in io.Reader, out io.Writer) ([]int, bool) {
	fmt.Fprintln(out, Bold(title))
	for i, it := range items {
		mark := " "
		if it.Checked {
			mark = "x"
		}
		fmt.Fprintf(out, "  %2d. [%s] %s\n", i+1, mark, it.Label)
		if it.SubLabel != "" {
			fmt.Fprintf(out, "       %s\n", Dim(it.SubLabel))
		}
	}
	fmt.Fprint(out, "Select which to check, e.g. 1,3 ('all' for all, Enter to keep the defaults shown above): ")

	scanner := bufio.NewScanner(in)
	if !scanner.Scan() {
		return nil, false
	}
	answer := scanner.Text()
	return parseSelection(answer, items)
}

func parseSelection(answer string, items []PickerItem) ([]int, bool) {
	answer = strings.TrimSpace(answer)
	if answer == "" {
		var picked []int
		for i, it := range items {
			if it.Checked {
				picked = append(picked, i)
			}
		}
		return picked, true
	}
	if answer == "all" {
		picked := make([]int, len(items))
		for i := range items {
			picked[i] = i
		}
		return picked, true
	}
	var picked []int
	for _, tok := range strings.Split(answer, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(tok))
		if err != nil || n < 1 || n > len(items) {
			continue
		}
		picked = append(picked, n-1)
	}
	return picked, true
}

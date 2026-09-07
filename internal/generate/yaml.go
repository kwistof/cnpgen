// Minimal, dependency-free YAML serializer for CiliumNetworkPolicy documents,
// with optional inline "# comment" annotations on CIDR list items.
//
// It works over an ordered document model (omap / oslice) so key order is
// deterministic and matches the hand-curated policy layout, and it quotes any
// scalar that would otherwise be misread as a number/bool (the CNP CRD requires
// port to be a string).

package generate

import (
	"strconv"
	"strings"
)

// omap is an insertion-ordered map used to build policy documents.
type omap struct {
	keys []string
	vals map[string]any
	// blockComment, if set, is rendered as one or more "# ..." lines directly
	// above this item when it appears as a list entry (e.g. a toFQDNs
	// matchName/matchPattern group). Ignored anywhere else.
	blockComment []string
}

func newOMap() *omap { return &omap{vals: map[string]any{}} }

func (m *omap) set(k string, v any) *omap {
	if _, ok := m.vals[k]; !ok {
		m.keys = append(m.keys, k)
	}
	m.vals[k] = v
	return m
}

func (m *omap) get(k string) (any, bool) {
	v, ok := m.vals[k]
	return v, ok
}

func (m *omap) len() int { return len(m.keys) }

// withComment attaches a block comment to be rendered above this item when
// it's a list entry.
func (m *omap) withComment(lines ...string) *omap {
	m.blockComment = lines
	return m
}

// commentLookup returns an inline comment for a CIDR list item, if any.
type commentLookup map[string]string

func yamlDump(obj any, indent int, comments commentLookup, sb *strings.Builder) {
	pad := strings.Repeat("  ", indent)
	switch v := obj.(type) {
	case *omap:
		for _, k := range v.keys {
			val := v.vals[k]
			switch child := val.(type) {
			case *omap:
				if child.len() == 0 {
					sb.WriteString(pad + k + ": {}\n")
				} else {
					sb.WriteString(pad + k + ":\n")
					yamlDump(child, indent+1, comments, sb)
				}
			case []any:
				if len(child) == 0 {
					sb.WriteString(pad + k + ": []\n")
				} else {
					sb.WriteString(pad + k + ":\n")
					yamlDump(child, indent+1, comments, sb)
				}
			default:
				sb.WriteString(pad + k + ": " + scalar(val) + "\n")
			}
		}
	case []any:
		for _, item := range v {
			switch it := item.(type) {
			case *omap:
				for _, line := range it.blockComment {
					sb.WriteString(pad + "# " + line + "\n")
				}
				first := true
				for _, k := range it.keys {
					val := it.vals[k]
					prefix := pad + "  "
					if first {
						prefix = pad + "- "
						first = false
					}
					switch child := val.(type) {
					case *omap:
						sb.WriteString(prefix + k + ":\n")
						yamlDump(child, indent+2, comments, sb)
					case []any:
						sb.WriteString(prefix + k + ":\n")
						yamlDump(child, indent+2, comments, sb)
					default:
						sb.WriteString(prefix + k + ": " + scalar(val) + "\n")
					}
				}
			case string:
				suffix := ""
				if c, ok := comments[it]; ok {
					suffix = " # " + c
				}
				sb.WriteString(pad + "- " + scalar(it) + suffix + "\n")
			default:
				sb.WriteString(pad + "- " + scalar(it) + "\n")
			}
		}
	default:
		sb.WriteString(pad + scalar(obj) + "\n")
	}
}

func looksNumeric(s string) bool {
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}

func scalar(v any) string {
	switch x := v.(type) {
	case bool:
		if x {
			return "true"
		}
		return "false"
	case int:
		return strconv.Itoa(x)
	case int32:
		return strconv.Itoa(int(x))
	}
	s := toString(v)
	low := strings.ToLower(s)
	if looksNumeric(s) || low == "true" || low == "false" || low == "null" || s == "~" {
		return `"` + s + `"`
	}
	if strings.ContainsAny(s, ":#{}[],&*?|<>=!%@`\"'") {
		return `"` + s + `"`
	}
	return s
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return strconv.Itoa(v.(int))
}

// toPlain converts the ordered document into a plain map/slice tree suitable
// for the dynamic Kubernetes client.
func toPlain(v any) any {
	switch x := v.(type) {
	case *omap:
		out := map[string]any{}
		for _, k := range x.keys {
			out[k] = toPlain(x.vals[k])
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = toPlain(item)
		}
		return out
	case int32:
		return int64(x)
	case int:
		return int64(x)
	default:
		return v
	}
}

// renderYAML serializes a policy document to a "---\n...\n" YAML string.
func renderYAML(doc *omap, comments commentLookup) string {
	var sb strings.Builder
	sb.WriteString("---\n")
	yamlDump(doc, 0, comments, &sb)
	return sb.String()
}

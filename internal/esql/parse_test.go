package esql

import (
	"reflect"
	"testing"
)

func TestParseFROM(t *testing.T) {
	p := Parse(`FROM equipe-a-logs | LIMIT 5`)
	if p.Uncertain || !reflect.DeepEqual(p.Indices, []string{"equipe-a-logs"}) || len(p.Policies) != 0 {
		t.Fatalf("got %+v", p)
	}
}

func TestParseFROMListAndQuoted(t *testing.T) {
	p := Parse(`FROM equipe-a-logs, "equipe-a-other" METADATA _id | KEEP host`)
	if p.Uncertain || !reflect.DeepEqual(p.Indices, []string{"equipe-a-logs", "equipe-a-other"}) {
		t.Fatalf("got %+v", p)
	}
}

func TestParseLOOKUPJOIN(t *testing.T) {
	p := Parse(`FROM equipe-a-logs | LOOKUP JOIN equipe-a-hosts ON host`)
	if p.Uncertain || !reflect.DeepEqual(p.Indices, []string{"equipe-a-logs", "equipe-a-hosts"}) {
		t.Fatalf("got %+v", p)
	}
}

func TestParseENRICH(t *testing.T) {
	p := Parse(`FROM equipe-a-sp05-logs | ENRICH sp05-owners-a-policy ON host | LIMIT 5`)
	if p.Uncertain || !reflect.DeepEqual(p.Indices, []string{"equipe-a-sp05-logs"}) || !reflect.DeepEqual(p.Policies, []string{"sp05-owners-a-policy"}) {
		t.Fatalf("got %+v", p)
	}
}

func TestParseCCSUncertain(t *testing.T) {
	p := Parse(`FROM remote:equipe-a-logs | LIMIT 1`)
	if !p.Uncertain {
		t.Fatalf("CCS must be uncertain, got %+v", p)
	}
}

func TestParseFORKUncertain(t *testing.T) {
	p := Parse(`FROM logs | FORK (WHERE true)`)
	if !p.Uncertain {
		t.Fatalf("FORK must be uncertain, got %+v", p)
	}
}

func TestParseMalformedUncertain(t *testing.T) {
	for _, q := range []string{"", "bad", "KEEP host", `FROM "unterminated`, "ENRICH p ON host"} {
		if p := Parse(q); !p.Uncertain {
			t.Fatalf("%q: want uncertain, got %+v", q, p)
		}
	}
}

func TestParseROWNoIndices(t *testing.T) {
	p := Parse(`ROW a = 1`)
	if p.Uncertain || len(p.Indices) != 0 || len(p.Policies) != 0 {
		t.Fatalf("got %+v", p)
	}
}

package velocity

import (
	"strings"
	"testing"
)

func TestRuleBasedNER_Email(t *testing.T) {
	ner := NewRuleBasedNER()
	entities := ner.Extract("Contact us at alice@example.com or bob@test.org for details")

	var emails []KGEntity
	for _, e := range entities {
		if e.Type == "EMAIL" {
			emails = append(emails, e)
		}
	}
	if len(emails) != 2 {
		t.Fatalf("expected 2 emails, got %d", len(emails))
	}
}

func TestRuleBasedNER_URL(t *testing.T) {
	ner := NewRuleBasedNER()
	entities := ner.Extract("Visit https://example.com/path and http://test.org")

	var urls []KGEntity
	for _, e := range entities {
		if e.Type == "URL" {
			urls = append(urls, e)
		}
	}
	if len(urls) != 2 {
		t.Fatalf("expected 2 URLs, got %d", len(urls))
	}
}

func TestRuleBasedNER_Date(t *testing.T) {
	ner := NewRuleBasedNER()
	entities := ner.Extract("The event is on 2024-03-15 and also March 20, 2024")

	var dates []KGEntity
	for _, e := range entities {
		if e.Type == "DATE" {
			dates = append(dates, e)
		}
	}
	if len(dates) < 2 {
		t.Fatalf("expected at least 2 dates, got %d", len(dates))
	}
}

func TestRuleBasedNER_Money(t *testing.T) {
	ner := NewRuleBasedNER()
	entities := ner.Extract("The price is $1,234.56 and 500 USD")

	var money []KGEntity
	for _, e := range entities {
		if e.Type == "MONEY" {
			money = append(money, e)
		}
	}
	if len(money) < 1 {
		t.Fatalf("expected at least 1 money entity, got %d", len(money))
	}
}

func TestRuleBasedNER_Org(t *testing.T) {
	ner := NewRuleBasedNER()
	entities := ner.Extract("We partnered with Acme Corp and Global Systems Inc to deliver the project")

	var orgs []KGEntity
	for _, e := range entities {
		if e.Type == "ORG" {
			orgs = append(orgs, e)
		}
	}
	if len(orgs) < 1 {
		t.Fatalf("expected at least 1 org, got %d: %+v", len(orgs), entities)
	}
}

func TestRuleBasedNER_Dedup(t *testing.T) {
	ner := NewRuleBasedNER()
	entities := ner.Extract("Email alice@example.com and also alice@example.com again")

	var emails []KGEntity
	for _, e := range entities {
		if e.Type == "EMAIL" {
			emails = append(emails, e)
		}
	}
	if len(emails) != 1 {
		t.Fatalf("expected dedup to 1 email, got %d", len(emails))
	}
}

func TestRuleBasedNER_AddRule(t *testing.T) {
	ner := NewRuleBasedNER()
	err := ner.AddRule("TICKET", `[A-Z]+-\d+`, 0.90)
	if err != nil {
		t.Fatal(err)
	}
	entities := ner.Extract("Fix JIRA-1234 and PROJ-5678")

	var tickets []KGEntity
	for _, e := range entities {
		if e.Type == "TICKET" {
			tickets = append(tickets, e)
		}
	}
	if len(tickets) != 2 {
		t.Fatalf("expected 2 tickets, got %d", len(tickets))
	}
}

func TestRuleBasedNER_Person(t *testing.T) {
	ner := NewRuleBasedNER()
	entities := ner.Extract("Dr. John Smith presented the findings alongside Mrs. Jane Doe")

	var persons []KGEntity
	for _, e := range entities {
		if e.Type == "PERSON" {
			persons = append(persons, e)
		}
	}
	if len(persons) < 1 {
		t.Fatalf("expected at least 1 person, got %d", len(persons))
	}
	found := false
	for _, p := range persons {
		if strings.Contains(p.Surface, "John Smith") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected to find 'John Smith', got %+v", persons)
	}
}

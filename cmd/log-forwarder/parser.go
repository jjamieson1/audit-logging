package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

type NormalizedEvent struct {
	App              string
	Level            string
	Message          string
	TimestampRaw     string
	ParserMode       string
	SourceFile       string
	SourceOffset     int64
	RawLine          string
	AdditionalFields map[string]any
}

type LineParser struct {
	cfg      Config
	compiled *regexp.Regexp
}

func NewLineParser(cfg Config) (*LineParser, error) {
	p := &LineParser{cfg: cfg}
	if cfg.ParserMode == "regex" {
		re, err := regexp.Compile(cfg.RegexPattern)
		if err != nil {
			return nil, fmt.Errorf("compile regex pattern: %w", err)
		}
		p.compiled = re
	}
	return p, nil
}

func (p *LineParser) Parse(event TailEvent) (NormalizedEvent, error) {
	line := strings.TrimSpace(event.Line)

	switch p.cfg.ParserMode {
	case "json":
		return p.parseJSONOnly(line, event)
	case "regex":
		return p.parseRegexOnly(line, event)
	case "custom":
		if parsed, ok := p.tryJSON(line, event); ok {
			return parsed, nil
		}
		if p.compiled != nil {
			if parsed, ok := p.tryRegex(line, event); ok {
				return parsed, nil
			}
		}
		return p.fallbackPlain(line, event), nil
	default:
		return NormalizedEvent{}, fmt.Errorf("unsupported parser_mode: %s", p.cfg.ParserMode)
	}
}

func (p *LineParser) parseJSONOnly(line string, event TailEvent) (NormalizedEvent, error) {
	parsed, ok := p.tryJSON(line, event)
	if !ok {
		return NormalizedEvent{}, fmt.Errorf("json parser could not parse line")
	}
	return parsed, nil
}

func (p *LineParser) parseRegexOnly(line string, event TailEvent) (NormalizedEvent, error) {
	if p.compiled == nil {
		return NormalizedEvent{}, fmt.Errorf("regex parser not configured")
	}
	parsed, ok := p.tryRegex(line, event)
	if !ok {
		return NormalizedEvent{}, fmt.Errorf("regex parser could not parse line")
	}
	return parsed, nil
}

func (p *LineParser) tryJSON(line string, event TailEvent) (NormalizedEvent, bool) {
	if line == "" {
		return NormalizedEvent{}, false
	}

	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return NormalizedEvent{}, false
	}

	message := stringFromAny(raw["message"])
	if message == "" {
		message = line
	}
	level := strings.ToUpper(stringFromAny(raw["level"]))
	if level == "" {
		level = p.cfg.DefaultLevel
	}
	ts := stringFromAny(raw[p.cfg.TimestampField])

	metadata := map[string]any{}
	for k, v := range raw {
		if k == "message" || k == "level" || k == p.cfg.TimestampField {
			continue
		}
		metadata[k] = v
	}

	return p.withBase(NormalizedEvent{
		Level:            level,
		Message:          message,
		TimestampRaw:     ts,
		ParserMode:       "json",
		RawLine:          line,
		AdditionalFields: metadata,
	}, event), true
}

func (p *LineParser) tryRegex(line string, event TailEvent) (NormalizedEvent, bool) {
	if p.compiled == nil {
		return NormalizedEvent{}, false
	}
	matches := p.compiled.FindStringSubmatch(line)
	if matches == nil {
		return NormalizedEvent{}, false
	}

	names := p.compiled.SubexpNames()
	fields := map[string]any{}
	for i := 1; i < len(matches); i++ {
		name := names[i]
		if name == "" {
			continue
		}
		fields[name] = matches[i]
	}

	message := stringFromAny(fields["message"])
	if message == "" {
		message = line
	}
	level := strings.ToUpper(stringFromAny(fields["level"]))
	if level == "" {
		level = p.cfg.DefaultLevel
	}
	ts := stringFromAny(fields[p.cfg.TimestampField])

	delete(fields, "message")
	delete(fields, "level")
	delete(fields, p.cfg.TimestampField)

	return p.withBase(NormalizedEvent{
		Level:            level,
		Message:          message,
		TimestampRaw:     ts,
		ParserMode:       "regex",
		RawLine:          line,
		AdditionalFields: fields,
	}, event), true
}

func (p *LineParser) fallbackPlain(line string, event TailEvent) NormalizedEvent {
	return p.withBase(NormalizedEvent{
		Level:        p.cfg.DefaultLevel,
		Message:      line,
		ParserMode:   "plain",
		RawLine:      line,
		TimestampRaw: "",
		AdditionalFields: map[string]any{
			"unparsed": true,
		},
	}, event)
}

func (p *LineParser) withBase(parsed NormalizedEvent, event TailEvent) NormalizedEvent {
	parsed.App = p.cfg.AppName
	parsed.SourceFile = event.SourceFile
	parsed.SourceOffset = event.CommittedOffset
	if parsed.AdditionalFields == nil {
		parsed.AdditionalFields = map[string]any{}
	}
	return parsed
}

func stringFromAny(value any) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case json.Number:
		return strings.TrimSpace(v.String())
	default:
		return ""
	}
}

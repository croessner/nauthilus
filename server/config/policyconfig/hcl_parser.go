// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyconfig

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
)

type hclTokenKind uint8

const (
	hclTokenEOF hclTokenKind = iota
	hclTokenWord
	hclTokenString
	hclTokenLeftBrace
	hclTokenRightBrace
	hclTokenLeftBracket
	hclTokenRightBracket
	hclTokenEquals
	hclTokenComma
)

type hclToken struct {
	kind  hclTokenKind
	value string
	line  int
}

type hclLexer struct {
	input []rune
	index int
	line  int
}

type hclParser struct {
	lexer   *hclLexer
	current hclToken
	depth   int
}

// decodeHCLSettings parses the bounded object/list/scalar subset used by policy configuration.
func decodeHCLSettings(reader io.Reader) (map[string]any, error) {
	data, err := readBoundedSettings(reader)
	if err != nil {
		return nil, fmt.Errorf("read HCL configuration: %w", err)
	}

	parser := &hclParser{lexer: &hclLexer{input: []rune(string(data)), line: 1}}
	if err := parser.advance(); err != nil {
		return nil, err
	}

	result, err := parser.parseAssignments(hclTokenEOF)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// advance consumes one lexical token.
func (p *hclParser) advance() error {
	token, err := p.lexer.next()
	if err != nil {
		return err
	}

	p.current = token

	return nil
}

// parseAssignments parses keyed values or HCL-style nested blocks.
func (p *hclParser) parseAssignments(terminator hclTokenKind) (map[string]any, error) {
	result := map[string]any{}

	for p.current.kind != terminator {
		if p.current.kind == hclTokenEOF {
			return nil, fmt.Errorf("line %d: unexpected end of HCL object", p.current.line)
		}

		if p.current.kind == hclTokenComma {
			if err := p.advance(); err != nil {
				return nil, err
			}

			continue
		}

		if p.current.kind != hclTokenWord && p.current.kind != hclTokenString {
			return nil, fmt.Errorf("line %d: expected HCL field name", p.current.line)
		}

		key := strings.ToLower(p.current.value)
		if _, exists := result[key]; exists {
			return nil, fmt.Errorf("line %d: duplicate HCL field %q", p.current.line, key)
		}

		if err := p.advance(); err != nil {
			return nil, err
		}

		value, err := p.parseAssignedValue()
		if err != nil {
			return nil, err
		}

		result[key] = value
	}

	if terminator != hclTokenEOF {
		return result, p.advance()
	}

	return result, nil
}

// parseAssignedValue parses either equals syntax or an HCL nested block.
func (p *hclParser) parseAssignedValue() (any, error) {
	if p.current.kind == hclTokenEquals {
		if err := p.advance(); err != nil {
			return nil, err
		}

		return p.parseValue()
	}

	if p.current.kind == hclTokenLeftBrace {
		return p.parseObject()
	}

	return nil, fmt.Errorf("line %d: expected '=' or nested HCL block", p.current.line)
}

// parseValue parses one scalar, object, or list value.
func (p *hclParser) parseValue() (any, error) {
	switch p.current.kind {
	case hclTokenString:
		value := p.current.value

		return value, p.advance()
	case hclTokenWord:
		value := parseHCLScalar(p.current.value)

		return value, p.advance()
	case hclTokenLeftBrace:
		return p.parseObject()
	case hclTokenLeftBracket:
		return p.parseList()
	default:
		return nil, fmt.Errorf("line %d: expected HCL value", p.current.line)
	}
}

// parseObject enters one bounded HCL object and parses its assignments.
func (p *hclParser) parseObject() (map[string]any, error) {
	if err := p.enterNesting(); err != nil {
		return nil, err
	}

	defer p.leaveNesting()

	if err := p.advance(); err != nil {
		return nil, err
	}

	return p.parseAssignments(hclTokenRightBrace)
}

// parseList parses one bounded comma-optional HCL list.
func (p *hclParser) parseList() ([]any, error) {
	if err := p.enterNesting(); err != nil {
		return nil, err
	}

	defer p.leaveNesting()

	if err := p.advance(); err != nil {
		return nil, err
	}

	result := make([]any, 0)

	for p.current.kind != hclTokenRightBracket {
		if p.current.kind == hclTokenEOF {
			return nil, fmt.Errorf("line %d: unexpected end of HCL list", p.current.line)
		}

		if p.current.kind == hclTokenComma {
			if err := p.advance(); err != nil {
				return nil, err
			}

			continue
		}

		value, err := p.parseValue()
		if err != nil {
			return nil, err
		}

		result = append(result, value)
	}

	return result, p.advance()
}

// enterNesting reserves one shared recursive-codec depth level.
func (p *hclParser) enterNesting() error {
	if err := validateNestingDepth(p.depth); err != nil {
		return err
	}

	p.depth++

	return nil
}

// leaveNesting releases one recursive-codec depth level.
func (p *hclParser) leaveNesting() {
	p.depth--
}

// parseHCLScalar converts exact booleans and numbers while retaining identifiers and durations.
func parseHCLScalar(value string) any {
	if boolean, err := strconv.ParseBool(value); err == nil {
		return boolean
	}

	if integer, err := strconv.ParseInt(value, 10, 64); err == nil {
		return integer
	}

	if decimal, err := strconv.ParseFloat(value, 64); err == nil {
		return decimal
	}

	return value
}

// next scans one HCL token while discarding whitespace and comments.
func (l *hclLexer) next() (hclToken, error) {
	if err := l.skipSpaceAndComments(); err != nil {
		return hclToken{}, err
	}

	if l.index >= len(l.input) {
		return hclToken{kind: hclTokenEOF, line: l.line}, nil
	}

	current := l.input[l.index]
	line := l.line
	l.index++

	switch current {
	case '{':
		return hclToken{kind: hclTokenLeftBrace, line: line}, nil
	case '}':
		return hclToken{kind: hclTokenRightBrace, line: line}, nil
	case '[':
		return hclToken{kind: hclTokenLeftBracket, line: line}, nil
	case ']':
		return hclToken{kind: hclTokenRightBracket, line: line}, nil
	case '=':
		return hclToken{kind: hclTokenEquals, line: line}, nil
	case ',':
		return hclToken{kind: hclTokenComma, line: line}, nil
	case '"':
		return l.scanQuoted(line)
	default:
		return l.scanWord(current, line)
	}
}

// skipSpaceAndComments advances past HCL whitespace and line/block comments.
func (l *hclLexer) skipSpaceAndComments() error {
	for l.index < len(l.input) {
		current := l.input[l.index]
		if unicode.IsSpace(current) {
			if current == '\n' {
				l.line++
			}

			l.index++

			continue
		}

		if current == '#' {
			l.skipLineComment()

			continue
		}

		if current == '/' && l.index+1 < len(l.input) && l.input[l.index+1] == '/' {
			l.skipLineComment()

			continue
		}

		if current == '/' && l.index+1 < len(l.input) && l.input[l.index+1] == '*' {
			if err := l.skipBlockComment(); err != nil {
				return err
			}

			continue
		}

		break
	}

	return nil
}

// skipLineComment advances to the next physical line.
func (l *hclLexer) skipLineComment() {
	for l.index < len(l.input) && l.input[l.index] != '\n' {
		l.index++
	}
}

// skipBlockComment advances through one bounded C-style comment.
func (l *hclLexer) skipBlockComment() error {
	startLine := l.line
	l.index += 2

	for l.index+1 < len(l.input) {
		if l.input[l.index] == '\n' {
			l.line++
		}

		if l.input[l.index] == '*' && l.input[l.index+1] == '/' {
			l.index += 2

			return nil
		}

		l.index++
	}

	return fmt.Errorf("line %d: unterminated HCL block comment", startLine)
}

// scanQuoted scans and unescapes one double-quoted HCL string.
func (l *hclLexer) scanQuoted(line int) (hclToken, error) {
	start := l.index - 1
	escaped := false

	for l.index < len(l.input) {
		current := l.input[l.index]
		l.index++

		if current == '\n' {
			l.line++
		}

		if escaped {
			escaped = false

			continue
		}

		if current == '\\' {
			escaped = true

			continue
		}

		if current == '"' {
			raw := string(l.input[start:l.index])

			value, err := strconv.Unquote(raw)
			if err != nil {
				return hclToken{}, fmt.Errorf("line %d: invalid HCL string: %w", line, err)
			}

			return hclToken{kind: hclTokenString, value: value, line: line}, nil
		}
	}

	return hclToken{}, fmt.Errorf("line %d: unterminated HCL string", line)
}

// scanWord scans one unquoted HCL identifier, scalar, or duration.
func (l *hclLexer) scanWord(first rune, line int) (hclToken, error) {
	word := []rune{first}

	for l.index < len(l.input) {
		current := l.input[l.index]
		if unicode.IsSpace(current) || strings.ContainsRune("{}[]=,", current) || current == '#' {
			break
		}

		word = append(word, current)
		l.index++
	}

	value := strings.TrimSpace(string(word))
	if value == "" {
		return hclToken{}, fmt.Errorf("line %d: empty HCL token", line)
	}

	return hclToken{kind: hclTokenWord, value: value, line: line}, nil
}

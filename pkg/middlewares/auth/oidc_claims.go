package auth

import (
	"fmt"
	"strconv"
	"strings"
)

type tokenClaims struct {
	idToken     map[string]any
	accessToken map[string]any
}

type claimsExpression interface {
	Eval(claims tokenClaims) bool
	NeedsAccessToken() bool
}

type claimsFunc struct {
	name string
	args []string
}

func (c *claimsFunc) Eval(claims tokenClaims) bool {
	if len(c.args) == 0 {
		return false
	}

	key := c.args[0]
	tokenKind, claimKey := splitTokenKey(key)
	var source map[string]any
	switch tokenKind {
	case "access_token":
		source = claims.accessToken
	default:
		source = claims.idToken
	}

	value, ok := lookupClaim(source, claimKey)
	if !ok {
		return false
	}

	switch strings.ToLower(c.name) {
	case "equals":
		if len(c.args) < 2 {
			return false
		}
		return claimEquals(value, c.args[1])
	case "prefix":
		if len(c.args) < 2 {
			return false
		}
		claimValue, ok := value.(string)
		if !ok {
			return false
		}
		return strings.HasPrefix(claimValue, c.args[1])
	case "contains":
		if len(c.args) < 2 {
			return false
		}
		return claimContains(value, c.args[1])
	case "splitcontains":
		if len(c.args) < 3 {
			return false
		}
		claimValue, ok := value.(string)
		if !ok {
			return false
		}
		parts := strings.Split(claimValue, c.args[1])
		for _, part := range parts {
			if part == c.args[2] {
				return true
			}
		}
		return false
	case "oneof":
		if len(c.args) < 2 {
			return false
		}
		return claimOneOf(value, c.args[1:])
	default:
		return false
	}
}

func (c *claimsFunc) NeedsAccessToken() bool {
	if len(c.args) == 0 {
		return false
	}
	tokenKind, _ := splitTokenKey(c.args[0])
	return tokenKind == "access_token"
}

type claimsNot struct {
	node claimsExpression
}

func (c *claimsNot) Eval(claims tokenClaims) bool {
	return !c.node.Eval(claims)
}

func (c *claimsNot) NeedsAccessToken() bool {
	return c.node.NeedsAccessToken()
}

type claimsBinary struct {
	left  claimsExpression
	right claimsExpression
	op    string
}

func (c *claimsBinary) Eval(claims tokenClaims) bool {
	switch c.op {
	case "&&":
		return c.left.Eval(claims) && c.right.Eval(claims)
	case "||":
		return c.left.Eval(claims) || c.right.Eval(claims)
	default:
		return false
	}
}

func (c *claimsBinary) NeedsAccessToken() bool {
	return c.left.NeedsAccessToken() || c.right.NeedsAccessToken()
}

type claimsParser struct {
	input string
	pos   int
}

func parseClaimsExpression(expr string) (claimsExpression, error) {
	parser := &claimsParser{input: expr}
	parser.skipSpace()
	if parser.eof() {
		return nil, nil
	}
	node, err := parser.parseOr()
	if err != nil {
		return nil, err
	}
	parser.skipSpace()
	if !parser.eof() {
		return nil, fmt.Errorf("unexpected token at position %d", parser.pos)
	}
	return node, nil
}

func (p *claimsParser) parseOr() (claimsExpression, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		p.skipSpace()
		if !p.consume("||") {
			break
		}
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &claimsBinary{left: left, right: right, op: "||"}
	}
	return left, nil
}

func (p *claimsParser) parseAnd() (claimsExpression, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		p.skipSpace()
		if !p.consume("&&") {
			break
		}
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &claimsBinary{left: left, right: right, op: "&&"}
	}
	return left, nil
}

func (p *claimsParser) parseUnary() (claimsExpression, error) {
	p.skipSpace()
	if p.consume("!") {
		node, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &claimsNot{node: node}, nil
	}
	return p.parseFunc()
}

func (p *claimsParser) parseFunc() (claimsExpression, error) {
	p.skipSpace()
	name := p.parseIdentifier()
	if name == "" {
		return nil, fmt.Errorf("expected function name at position %d", p.pos)
	}
	p.skipSpace()
	if !p.consume("(") {
		return nil, fmt.Errorf("expected '(' after %s at position %d", name, p.pos)
	}
	args, err := p.parseArgs()
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	if !p.consume(")") {
		return nil, fmt.Errorf("expected ')' after %s at position %d", name, p.pos)
	}
	return &claimsFunc{name: name, args: args}, nil
}

func (p *claimsParser) parseArgs() ([]string, error) {
	var args []string
	for {
		p.skipSpace()
		if p.peek() == ')' {
			break
		}
		arg, err := p.parseBacktickString()
		if err != nil {
			return nil, err
		}
		args = append(args, arg)
		p.skipSpace()
		if p.consume(",") {
			continue
		}
		break
	}
	return args, nil
}

func (p *claimsParser) parseIdentifier() string {
	start := p.pos
	for !p.eof() {
		ch := p.peek()
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' {
			p.pos++
			continue
		}
		break
	}
	if start == p.pos {
		return ""
	}
	return p.input[start:p.pos]
}

func (p *claimsParser) parseBacktickString() (string, error) {
	if !p.consume("`") {
		return "", fmt.Errorf("expected '`' at position %d", p.pos)
	}
	var builder strings.Builder
	for !p.eof() {
		ch := p.peek()
		p.pos++
		if ch == '`' {
			return builder.String(), nil
		}
		if ch == '\\' && !p.eof() {
			next := p.peek()
			p.pos++
			builder.WriteRune(next)
			continue
		}
		builder.WriteRune(ch)
	}
	return "", fmt.Errorf("unterminated string")
}

func (p *claimsParser) skipSpace() {
	for !p.eof() {
		switch p.peek() {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *claimsParser) consume(value string) bool {
	if strings.HasPrefix(p.input[p.pos:], value) {
		p.pos += len(value)
		return true
	}
	return false
}

func (p *claimsParser) peek() rune {
	if p.eof() {
		return 0
	}
	return rune(p.input[p.pos])
}

func (p *claimsParser) eof() bool {
	return p.pos >= len(p.input)
}

func splitTokenKey(key string) (string, string) {
	if strings.HasPrefix(key, "id_token.") {
		return "id_token", strings.TrimPrefix(key, "id_token.")
	}
	if strings.HasPrefix(key, "access_token.") {
		return "access_token", strings.TrimPrefix(key, "access_token.")
	}
	return "id_token", key
}

func lookupClaim(claims map[string]any, key string) (any, bool) {
	if claims == nil {
		return nil, false
	}
	path := splitClaimPath(key)
	var current any = claims
	for _, segment := range path {
		obj, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		value, ok := obj[segment]
		if !ok {
			return nil, false
		}
		current = value
	}
	return current, true
}

func splitClaimPath(key string) []string {
	var parts []string
	var builder strings.Builder
	escaped := false
	for _, ch := range key {
		if escaped {
			builder.WriteRune(ch)
			escaped = false
			continue
		}
		switch ch {
		case '\\':
			escaped = true
		case '.':
			parts = append(parts, builder.String())
			builder.Reset()
		default:
			builder.WriteRune(ch)
		}
	}
	if builder.Len() > 0 || len(parts) == 0 {
		parts = append(parts, builder.String())
	}
	return parts
}

func claimEquals(value any, expected string) bool {
	switch v := value.(type) {
	case bool:
		parsed, err := strconv.ParseBool(expected)
		if err != nil {
			return false
		}
		return v == parsed
	case float64:
		parsed, err := strconv.ParseFloat(expected, 64)
		if err != nil {
			return false
		}
		return v == parsed
	case string:
		return v == expected
	default:
		return fmt.Sprint(value) == expected
	}
}

func claimContains(value any, expected string) bool {
	switch v := value.(type) {
	case string:
		return strings.Contains(v, expected)
	case []any:
		for _, item := range v {
			if fmt.Sprint(item) == expected {
				return true
			}
		}
	case []string:
		for _, item := range v {
			if item == expected {
				return true
			}
		}
	}
	return false
}

func claimOneOf(value any, candidates []string) bool {
	switch v := value.(type) {
	case string:
		for _, candidate := range candidates {
			if v == candidate {
				return true
			}
		}
	case []any:
		for _, item := range v {
			itemValue := fmt.Sprint(item)
			for _, candidate := range candidates {
				if itemValue == candidate {
					return true
				}
			}
		}
	case []string:
		for _, item := range v {
			for _, candidate := range candidates {
				if item == candidate {
					return true
				}
			}
		}
	}
	return false
}

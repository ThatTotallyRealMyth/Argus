package searchquery

import (
	"fmt"
	"strings"
	"unicode"

	"gorm.io/gorm"
)

type tokenKind uint8

const (
	tokenEOF tokenKind = iota
	tokenTerm
	tokenAnd
	tokenOr
	tokenNot
	tokenLeftParen
	tokenRightParen
)

type token struct {
	kind  tokenKind
	value string
	pos   int
}

type node struct {
	kind        tokenKind
	value       string
	left, right *node
}

type parser struct {
	tokens []token
	index  int
}

// Apply parses the user expression and applies a parameterized WHERE clause.
// Field names and SQL columns must be supplied by the caller as a whitelist.
func Apply(query *gorm.DB, raw string, fields map[string]string, defaultColumns []string) (*gorm.DB, error) {
	if strings.TrimSpace(raw) == "" {
		return query, nil
	}
	tokens, err := lex(raw)
	if err != nil {
		return query, err
	}
	p := parser{tokens: tokens}
	root, err := p.parseExpression()
	if err != nil {
		return query, err
	}
	if current := p.current(); current.kind != tokenEOF {
		return query, fmt.Errorf("位置 %d 附近存在多余内容", current.pos+1)
	}
	where, args, err := compile(root, fields, defaultColumns)
	if err != nil {
		return query, err
	}
	return query.Where(where, args...), nil
}

func lex(raw string) ([]token, error) {
	result := make([]token, 0, 12)
	runes := []rune(raw)
	for i := 0; i < len(runes); {
		if unicode.IsSpace(runes[i]) {
			i++
			continue
		}
		start := i
		switch runes[i] {
		case '&':
			if i+1 >= len(runes) || runes[i+1] != '&' {
				return nil, fmt.Errorf("位置 %d：AND 运算符应写为 &&", i+1)
			}
			result = append(result, token{kind: tokenAnd, pos: i})
			i += 2
			continue
		case '|':
			if i+1 >= len(runes) || runes[i+1] != '|' {
				return nil, fmt.Errorf("位置 %d：OR 运算符应写为 ||", i+1)
			}
			result = append(result, token{kind: tokenOr, pos: i})
			i += 2
			continue
		case '!':
			if i+1 < len(runes) && runes[i+1] == '=' {
				break
			}
			result = append(result, token{kind: tokenNot, pos: i})
			i++
			continue
		case '(':
			result = append(result, token{kind: tokenLeftParen, pos: i})
			i++
			continue
		case ')':
			result = append(result, token{kind: tokenRightParen, pos: i})
			i++
			continue
		}

		var value strings.Builder
		quoted := false
		for i < len(runes) {
			ch := runes[i]
			if ch == '"' {
				quoted = !quoted
				i++
				continue
			}
			notEquals := ch == '!' && i+1 < len(runes) && runes[i+1] == '='
			if !quoted && (unicode.IsSpace(ch) || ch == '&' || ch == '|' || (ch == '!' && !notEquals) || ch == '(' || ch == ')') {
				break
			}
			if ch == '\\' && quoted && i+1 < len(runes) && runes[i+1] == '"' {
				value.WriteRune('"')
				i += 2
				continue
			}
			value.WriteRune(ch)
			i++
		}
		if quoted {
			return nil, fmt.Errorf("位置 %d：双引号未闭合", start+1)
		}
		if strings.TrimSpace(value.String()) == "" {
			return nil, fmt.Errorf("位置 %d：检索词不能为空", start+1)
		}
		result = append(result, token{kind: tokenTerm, value: value.String(), pos: start})
	}
	result = append(result, token{kind: tokenEOF, pos: len(runes)})
	return result, nil
}

func (p *parser) current() token { return p.tokens[p.index] }
func (p *parser) advance() token { value := p.current(); p.index++; return value }

func (p *parser) parseExpression() (*node, error) { return p.parseOr() }

func (p *parser) parseOr() (*node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.current().kind == tokenOr {
		operator := p.advance()
		if p.current().kind == tokenEOF || p.current().kind == tokenRightParen {
			return nil, fmt.Errorf("位置 %d：|| 后缺少条件", operator.pos+1)
		}
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &node{kind: tokenOr, left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseAnd() (*node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		explicit := p.current().kind == tokenAnd
		implicit := p.current().kind == tokenTerm || p.current().kind == tokenNot || p.current().kind == tokenLeftParen
		if !explicit && !implicit {
			break
		}
		if explicit {
			operator := p.advance()
			if p.current().kind == tokenEOF || p.current().kind == tokenRightParen || p.current().kind == tokenOr {
				return nil, fmt.Errorf("位置 %d：&& 后缺少条件", operator.pos+1)
			}
		}
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &node{kind: tokenAnd, left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseUnary() (*node, error) {
	if p.current().kind == tokenNot {
		operator := p.advance()
		if p.current().kind == tokenEOF || p.current().kind == tokenRightParen {
			return nil, fmt.Errorf("位置 %d：! 后缺少条件", operator.pos+1)
		}
		value, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &node{kind: tokenNot, left: value}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (*node, error) {
	current := p.current()
	switch current.kind {
	case tokenTerm:
		p.advance()
		return &node{kind: tokenTerm, value: current.value}, nil
	case tokenLeftParen:
		p.advance()
		if p.current().kind == tokenRightParen {
			return nil, fmt.Errorf("位置 %d：括号内不能为空", current.pos+1)
		}
		value, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		if p.current().kind != tokenRightParen {
			return nil, fmt.Errorf("位置 %d：缺少右括号", current.pos+1)
		}
		p.advance()
		return value, nil
	default:
		return nil, fmt.Errorf("位置 %d：需要检索条件", current.pos+1)
	}
}

func compile(value *node, fields map[string]string, defaults []string) (string, []any, error) {
	switch value.kind {
	case tokenAnd, tokenOr:
		leftSQL, leftArgs, err := compile(value.left, fields, defaults)
		if err != nil {
			return "", nil, err
		}
		rightSQL, rightArgs, err := compile(value.right, fields, defaults)
		if err != nil {
			return "", nil, err
		}
		operator := "AND"
		if value.kind == tokenOr {
			operator = "OR"
		}
		return "(" + leftSQL + " " + operator + " " + rightSQL + ")", append(leftArgs, rightArgs...), nil
	case tokenNot:
		innerSQL, args, err := compile(value.left, fields, defaults)
		if err != nil {
			return "", nil, err
		}
		return "NOT (" + innerSQL + ")", args, nil
	case tokenTerm:
		field, term, comparison, operatorLength := "", value.value, "contains", 1
		separator := strings.Index(value.value, ":")
		if equals := strings.Index(value.value, "="); equals >= 0 && (separator < 0 || equals < separator) {
			separator = equals
			comparison = "equals"
			if equals > 0 && value.value[equals-1] == '!' {
				separator = equals - 1
				comparison = "not-equals"
				operatorLength = 2
			}
		}
		if separator > 0 {
			field, term = strings.ToLower(strings.TrimSpace(value.value[:separator])), strings.TrimSpace(value.value[separator+operatorLength:])
			if term == "" {
				return "", nil, fmt.Errorf("字段 %s 缺少检索值", field)
			}
		}
		columns := defaults
		if field != "" {
			column, ok := fields[field]
			if !ok {
				return "", nil, fmt.Errorf("不支持字段 %s", field)
			}
			columns = []string{column}
		}
		if len(columns) == 0 {
			return "", nil, fmt.Errorf("当前列表没有可检索字段")
		}
		parts := make([]string, 0, len(columns))
		args := make([]any, 0, len(columns))
		for _, column := range columns {
			clause := "LOWER(COALESCE(" + column + "::text, '')) LIKE ?"
			if comparison == "equals" || comparison == "not-equals" {
				clause = "LOWER(COALESCE(" + column + "::text, '')) = ?"
			}
			if comparison == "not-equals" {
				clause = "NOT (" + clause + ")"
			}
			parts = append(parts, clause)
			args = append(args, "%"+strings.ToLower(term)+"%")
			if comparison == "equals" || comparison == "not-equals" {
				args[len(args)-1] = strings.ToLower(term)
			}
		}
		return "(" + strings.Join(parts, " OR ") + ")", args, nil
	default:
		return "", nil, fmt.Errorf("无效检索表达式")
	}
}

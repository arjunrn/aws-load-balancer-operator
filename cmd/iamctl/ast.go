package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/format"
	"go/token"
	"os"
	"text/template"
)

func buildStrings(input interface{}) ast.Expr {
	switch val := input.(type) {
	case string:
		return &ast.BasicLit{
			Kind:  token.STRING,
			Value: fmt.Sprintf(`"%s"`, val),
		}
	case []string:
		ret := make([]ast.Expr, 0, len(val))
		for _, s := range val {
			ret = append(ret, buildStrings(s))
		}
		return &ast.CompositeLit{
			Type: ast.NewIdent("[]string"),
			Elts: ret,
		}
	case AWSValue:
		ret := make([]ast.Expr, 0, len(val))
		for _, s := range val {
			ret = append(ret, buildStrings(s))
		}
		return &ast.CompositeLit{
			Type: ast.NewIdent("[]string"),
			Elts: ret,
		}
	default:
		panic("unsupported type for string expr")
	}
}

func buildKeyValueExpr(input interface{}) ast.Expr {
	switch val := input.(type) {
	case *iamPolicyCondition:
		if val == nil {
			return ast.NewIdent("nil")
		}
		exprs := make([]ast.Expr, 0, 1)

		for k, v := range *val {
			exprs = append(exprs, &ast.KeyValueExpr{
				Key:   buildStrings(k),
				Value: buildKeyValueExpr(v),
			})
		}
		return &ast.CompositeLit{
			Type: &ast.SelectorExpr{
				X:   ast.NewIdent("cco"),
				Sel: ast.NewIdent("IAMPolicyCondition"),
			},
			Elts: exprs,
		}
	case iamPolicyConditionKeyValue:
		exprs := make([]ast.Expr, 0, 1)
		for k, v := range val {
			exprs = append(exprs, &ast.KeyValueExpr{
				Key:   buildStrings(k),
				Value: buildStrings(v),
			})
		}
		return &ast.CompositeLit{
			Type: &ast.SelectorExpr{
				X:   ast.NewIdent("cco"),
				Sel: ast.NewIdent("IAMPolicyConditionKeyValue"),
			},
			Elts: exprs,
		}
	default:
		panic("unsupported type for key/val expr")
	}
}

func generateIAMPolicy(input, output, pkg string, shouldMinify bool) {
	tmpl, err := template.New("").Parse(filetemplate)
	if err != nil {
		panic(err)
	}

	policy := iamPolicy{}

	inputFile, err := os.Open(input)
	if err != nil {
		panic(fmt.Sprintf("failed to open input file %s: %v", input, err))
	}

	decoder := json.NewDecoder(inputFile)
	err = decoder.Decode(&policy)
	if err != nil {
		panic(fmt.Sprintf("failed to parse input file %s: %v", input, err))
	}

	// Minifying here as a workaround for current limitations
	// in credential requests length (2048 max bytes).
	if shouldMinify {
		policy = minify(policy)
	}

	var policyOutput bytes.Buffer

	fmt.Fprintf(&policyOutput, "Version: %q,\n", policy.Version)
	fmt.Fprintf(&policyOutput, "\t\tStatement: []cco.StatementEntry{\n")
	for _, p := range policy.Statement {
		for _, r := range p.Resource {
			fmt.Fprintf(&policyOutput, "\t\t\t{\n")
			fmt.Fprintf(&policyOutput, "\t\t\t\tEffect: %q,\n", p.Effect)
			if p.Condition != nil {
				fmt.Fprintf(&policyOutput, "\t\t\t\tCondition:{\n")
				for conditionKey, conditionValues := range *p.Condition {
					fmt.Fprintf(&policyOutput, "\t\t\t\t\t%q:{\n", conditionKey)
					for k, v := range conditionValues {
						fmt.Fprintf(&policyOutput, "\t\t\t\t\t\t%q:%q,\n", k, v)
					}
					fmt.Fprintf(&policyOutput, "\t\t\t\t\t},\n")
				}
				fmt.Fprintf(&policyOutput, "\t\t\t\t},\n")
			}
			fmt.Fprintf(&policyOutput, "\t\t\t\tAction: []string{\n")
			for _, a := range p.Action {
				fmt.Fprintf(&policyOutput, "\t\t\t\t\t%q,\n", a)
			}
			fmt.Fprintf(&policyOutput, "\t\t\t\t},\n")

			fmt.Fprintf(&policyOutput, "\t\t\t\tResource: %q,\n", r)

			fmt.Fprintf(&policyOutput, "\t\t\t},\n")
		}
	}
	fmt.Fprintf(&policyOutput, "\t\t},")

	var in bytes.Buffer
	tmplVar := struct {
		Package string
		Policy  string
	}{
		Package: pkg,
		Policy:  policyOutput.String(),
	}

	err = tmpl.Execute(&in, tmplVar)
	if err != nil {
		panic(err)
	}

	formatted, err := format.Source(in.Bytes())
	if err != nil {
		panic(err)
	}

	outputF, err := os.Create(output)
	if err != nil {
		panic(err)
	}
	_, err = outputF.Write(formatted)
	if err != nil {
		panic(err)
	}
}

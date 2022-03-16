package awsloadbalancercontroller

import cco "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"

type IAMPolicy struct {
	Version   string
	Statement []cco.StatementEntry
}

func GetIAMPolicy() IAMPolicy {
	return IAMPolicy{
		Version: "2012-10-17",
		Statement: []cco.StatementEntry{
			{
				Effect: "Allow",
				Condition: {
					"StringEquals": {
						"iam:AWSServiceName": "elasticloadbalancing.amazonaws.com",
					},
				},
				Action: []string{
					"iam:CreateServiceLinkedRole",
				},
				Resource: "*",
			},
			{
				Effect: "Allow",
				Action: []string{
					"ec2:DescribeAccountAttributes",
					"ec2:DescribeAddresses",
					"ec2:DescribeAvailabilityZones",
					"ec2:DescribeInternetGateways",
					"ec2:DescribeVpcs",
					"ec2:DescribeVpcPeeringConnections",
					"ec2:DescribeSubnets",
					"ec2:DescribeSecurityGroups",
					"ec2:DescribeInstances",
					"ec2:DescribeNetworkInterfaces",
					"ec2:DescribeTags",
					"ec2:GetCoipPoolUsage",
					"ec2:DescribeCoipPools",
					"elasticloadbalancing:DescribeLoadBalancers",
					"elasticloadbalancing:DescribeLoadBalancerAttributes",
					"elasticloadbalancing:DescribeListeners",
					"elasticloadbalancing:DescribeListenerCertificates",
					"elasticloadbalancing:DescribeSSLPolicies",
					"elasticloadbalancing:DescribeRules",
					"elasticloadbalancing:DescribeTargetGroups",
					"elasticloadbalancing:DescribeTargetGroupAttributes",
					"elasticloadbalancing:DescribeTargetHealth",
					"elasticloadbalancing:DescribeTags",
				},
				Resource: "*",
			},
			{
				Effect: "Allow",
				Action: []string{
					"cognito-idp:DescribeUserPoolClient",
					"acm:ListCertificates",
					"acm:DescribeCertificate",
					"iam:ListServerCertificates",
					"iam:GetServerCertificate",
					"waf-regional:GetWebACL",
					"waf-regional:GetWebACLForResource",
					"waf-regional:AssociateWebACL",
					"waf-regional:DisassociateWebACL",
					"wafv2:GetWebACL",
					"wafv2:GetWebACLForResource",
					"wafv2:AssociateWebACL",
					"wafv2:DisassociateWebACL",
					"shield:GetSubscriptionState",
					"shield:DescribeProtection",
					"shield:CreateProtection",
					"shield:DeleteProtection",
				},
				Resource: "*",
			},
			{
				Effect: "Allow",
				Action: []string{
					"ec2:AuthorizeSecurityGroupIngress",
					"ec2:RevokeSecurityGroupIngress",
				},
				Resource: "*",
			},
			{
				Effect: "Allow",
				Action: []string{
					"ec2:CreateSecurityGroup",
				},
				Resource: "*",
			},
			{
				Effect: "Allow",
				Condition: {
					"Null": {
						"aws:RequestTag/elbv2.k8s.aws/cluster": "false",
					},
					"StringEquals": {
						"ec2:CreateAction": "CreateSecurityGroup",
					},
				},
				Action: []string{
					"ec2:CreateTags",
				},
				Resource: "arn:aws:ec2:*:*:security-group/*",
			},
			{
				Effect: "Allow",
				Condition: {
					"Null": {
						"aws:RequestTag/elbv2.k8s.aws/cluster":  "true",
						"aws:ResourceTag/elbv2.k8s.aws/cluster": "false",
					},
				},
				Action: []string{
					"ec2:CreateTags",
					"ec2:DeleteTags",
				},
				Resource: "arn:aws:ec2:*:*:security-group/*",
			},
			{
				Effect: "Allow",
				Condition: {
					"Null": {
						"aws:ResourceTag/elbv2.k8s.aws/cluster": "false",
					},
				},
				Action: []string{
					"ec2:AuthorizeSecurityGroupIngress",
					"ec2:RevokeSecurityGroupIngress",
					"ec2:DeleteSecurityGroup",
				},
				Resource: "*",
			},
			{
				Effect: "Allow",
				Condition: {
					"Null": {
						"aws:RequestTag/elbv2.k8s.aws/cluster": "false",
					},
				},
				Action: []string{
					"elasticloadbalancing:CreateLoadBalancer",
					"elasticloadbalancing:CreateTargetGroup",
				},
				Resource: "*",
			},
			{
				Effect: "Allow",
				Action: []string{
					"elasticloadbalancing:CreateListener",
					"elasticloadbalancing:DeleteListener",
					"elasticloadbalancing:CreateRule",
					"elasticloadbalancing:DeleteRule",
				},
				Resource: "*",
			},
			{
				Effect: "Allow",
				Condition: {
					"Null": {
						"aws:RequestTag/elbv2.k8s.aws/cluster":  "true",
						"aws:ResourceTag/elbv2.k8s.aws/cluster": "false",
					},
				},
				Action: []string{
					"elasticloadbalancing:AddTags",
					"elasticloadbalancing:RemoveTags",
				},
				Resource: "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
			},
			{
				Effect: "Allow",
				Condition: {
					"Null": {
						"aws:RequestTag/elbv2.k8s.aws/cluster":  "true",
						"aws:ResourceTag/elbv2.k8s.aws/cluster": "false",
					},
				},
				Action: []string{
					"elasticloadbalancing:AddTags",
					"elasticloadbalancing:RemoveTags",
				},
				Resource: "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
			},
			{
				Effect: "Allow",
				Condition: {
					"Null": {
						"aws:RequestTag/elbv2.k8s.aws/cluster":  "true",
						"aws:ResourceTag/elbv2.k8s.aws/cluster": "false",
					},
				},
				Action: []string{
					"elasticloadbalancing:AddTags",
					"elasticloadbalancing:RemoveTags",
				},
				Resource: "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*",
			},
			{
				Effect: "Allow",
				Action: []string{
					"elasticloadbalancing:AddTags",
					"elasticloadbalancing:RemoveTags",
				},
				Resource: "arn:aws:elasticloadbalancing:*:*:listener/net/*/*/*",
			},
			{
				Effect: "Allow",
				Action: []string{
					"elasticloadbalancing:AddTags",
					"elasticloadbalancing:RemoveTags",
				},
				Resource: "arn:aws:elasticloadbalancing:*:*:listener/app/*/*/*",
			},
			{
				Effect: "Allow",
				Action: []string{
					"elasticloadbalancing:AddTags",
					"elasticloadbalancing:RemoveTags",
				},
				Resource: "arn:aws:elasticloadbalancing:*:*:listener-rule/net/*/*/*",
			},
			{
				Effect: "Allow",
				Action: []string{
					"elasticloadbalancing:AddTags",
					"elasticloadbalancing:RemoveTags",
				},
				Resource: "arn:aws:elasticloadbalancing:*:*:listener-rule/app/*/*/*",
			},
			{
				Effect: "Allow",
				Condition: {
					"Null": {
						"aws:ResourceTag/elbv2.k8s.aws/cluster": "false",
					},
				},
				Action: []string{
					"elasticloadbalancing:ModifyLoadBalancerAttributes",
					"elasticloadbalancing:SetIpAddressType",
					"elasticloadbalancing:SetSecurityGroups",
					"elasticloadbalancing:SetSubnets",
					"elasticloadbalancing:DeleteLoadBalancer",
					"elasticloadbalancing:ModifyTargetGroup",
					"elasticloadbalancing:ModifyTargetGroupAttributes",
					"elasticloadbalancing:DeleteTargetGroup",
				},
				Resource: "*",
			},
			{
				Effect: "Allow",
				Action: []string{
					"elasticloadbalancing:RegisterTargets",
					"elasticloadbalancing:DeregisterTargets",
				},
				Resource: "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
			},
			{
				Effect: "Allow",
				Action: []string{
					"elasticloadbalancing:SetWebAcl",
					"elasticloadbalancing:ModifyListener",
					"elasticloadbalancing:AddListenerCertificates",
					"elasticloadbalancing:RemoveListenerCertificates",
					"elasticloadbalancing:ModifyRule",
				},
				Resource: "*",
			},
		},
	}
}

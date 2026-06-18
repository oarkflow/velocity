package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/oarkflow/velocity"
	"github.com/oarkflow/velocity/pkg/compliance"
	"github.com/urfave/cli/v3"
)

func complianceCmd(db *velocity.DB) *cli.Command {
	return &cli.Command{
		Name:  "compliance",
		Usage: "Compliance management operations",
		Commands: []*cli.Command{
			{
				Name:  "tag",
				Usage: "Tag a resource with compliance metadata",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "type", Usage: "Resource type (kv, object, bucket, folder, secret, secret_version, sql_schema, sql_table, sql_column, sql_row)", Required: true},
					&cli.StringFlag{Name: "framework", Usage: "Compliance framework (GDPR, HIPAA, SOC2, etc.)", Required: true},
					&cli.StringFlag{Name: "class", Usage: "Data classification", Value: "internal"},
					&cli.StringFlag{Name: "owner", Usage: "Data owner"},
					&cli.StringFlag{Name: "custodian", Usage: "Data custodian"},
					&cli.BoolFlag{Name: "encrypt", Usage: "Require encryption"},
					&cli.StringFlag{Name: "audit", Usage: "Audit level"},
					&cli.StringFlag{Name: "access-policy", Usage: "Access policy"},
					&cli.StringFlag{Name: "created-by", Usage: "Creator identity", Value: "cli"},
					&cli.StringFlag{Name: "path", Usage: "Resource path (for kv, object, folder)"},
					&cli.StringFlag{Name: "bucket", Usage: "Bucket name (for bucket type)"},
					&cli.StringFlag{Name: "name", Usage: "Secret name (for secret, secret_version)"},
					&cli.StringFlag{Name: "version", Usage: "Secret version (for secret_version)"},
					&cli.StringFlag{Name: "schema", Usage: "SQL schema name", Value: "main"},
					&cli.StringFlag{Name: "table", Usage: "SQL table name"},
					&cli.StringFlag{Name: "column", Usage: "SQL column name"},
					&cli.StringFlag{Name: "row", Usage: "SQL row key"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					ref, err := complianceRefFromCmd(cmd)
					if err != nil {
						return err
					}
					ctm := db.ComplianceTagManager()
					if ctm == nil {
						ctm = velocity.NewComplianceTagManager(db)
						db.SetComplianceTagManager(ctm)
					}
					frameworks, err := parseComplianceFrameworks(cmd.String("framework"))
					if err != nil {
						return err
					}
					dataClass := compliance.DataClassification(cmd.String("class"))
					if dataClass == "" {
						dataClass = compliance.DataClassInternal
					}
					tag := &velocity.ComplianceTag{
						Frameworks:    frameworks,
						DataClass:     dataClass,
						Owner:         cmd.String("owner"),
						Custodian:     cmd.String("custodian"),
						EncryptionReq: cmd.Bool("encrypt"),
						AuditLevel:    cmd.String("audit"),
						AccessPolicy:  cmd.String("access-policy"),
						CreatedBy:     cmd.String("created-by"),
					}
					if err := ctm.TagResource(ctx, ref, tag); err != nil {
						return err
					}
					fmt.Printf("Tagged %s\n", tag.ResourceID)
					return nil
				},
			},
			{
				Name:  "get",
				Usage: "Get compliance tags for a resource",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "type", Usage: "Resource type", Required: true},
					&cli.StringFlag{Name: "path", Usage: "Resource path"},
					&cli.StringFlag{Name: "bucket", Usage: "Bucket name"},
					&cli.StringFlag{Name: "name", Usage: "Secret name"},
					&cli.StringFlag{Name: "version", Usage: "Secret version"},
					&cli.StringFlag{Name: "schema", Usage: "SQL schema name", Value: "main"},
					&cli.StringFlag{Name: "table", Usage: "SQL table name"},
					&cli.StringFlag{Name: "column", Usage: "SQL column name"},
					&cli.StringFlag{Name: "row", Usage: "SQL row key"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					ref, err := complianceRefFromCmd(cmd)
					if err != nil {
						return err
					}
					ctm := db.ComplianceTagManager()
					if ctm == nil {
						ctm = velocity.NewComplianceTagManager(db)
						db.SetComplianceTagManager(ctm)
					}
					tags := ctm.GetResourceTags(ref)
					return printJSON(tags)
				},
			},
			{
				Name:  "check",
				Usage: "Check compliance for a resource operation",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "type", Usage: "Resource type", Required: true},
					&cli.StringFlag{Name: "operation", Usage: "Operation (read, write, delete, share)", Value: "read"},
					&cli.StringFlag{Name: "actor", Usage: "User performing the operation"},
					&cli.StringFlag{Name: "region", Usage: "Geographic region"},
					&cli.StringFlag{Name: "subject-id", Usage: "Subject identifier"},
					&cli.StringFlag{Name: "purpose", Usage: "Purpose of access"},
					&cli.BoolFlag{Name: "encrypted", Usage: "Whether data is encrypted"},
					&cli.BoolFlag{Name: "mfa", Usage: "Whether MFA was verified"},
					&cli.StringFlag{Name: "crypto-algorithm", Usage: "Encryption algorithm used"},
					&cli.StringFlag{Name: "reason", Usage: "Reason for access"},
					&cli.StringFlag{Name: "path", Usage: "Resource path"},
					&cli.StringFlag{Name: "bucket", Usage: "Bucket name"},
					&cli.StringFlag{Name: "name", Usage: "Secret name"},
					&cli.StringFlag{Name: "version", Usage: "Secret version"},
					&cli.StringFlag{Name: "schema", Usage: "SQL schema name", Value: "main"},
					&cli.StringFlag{Name: "table", Usage: "SQL table name"},
					&cli.StringFlag{Name: "column", Usage: "SQL column name"},
					&cli.StringFlag{Name: "row", Usage: "SQL row key"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					ref, err := complianceRefFromCmd(cmd)
					if err != nil {
						return err
					}
					ctm := db.ComplianceTagManager()
					if ctm == nil {
						ctm = velocity.NewComplianceTagManager(db)
						db.SetComplianceTagManager(ctm)
					}
					req := &velocity.ComplianceOperationRequest{
						Operation:       cmd.String("operation"),
						Actor:           cmd.String("actor"),
						Region:          cmd.String("region"),
						SubjectID:       cmd.String("subject-id"),
						Purpose:         cmd.String("purpose"),
						Encrypted:       cmd.Bool("encrypted"),
						MFAVerified:     cmd.Bool("mfa"),
						CryptoAlgorithm: cmd.String("crypto-algorithm"),
						Reason:          cmd.String("reason"),
					}
					result, err := ctm.ValidateResourceOperation(ctx, ref, req)
					if err != nil {
						return err
					}
					return printJSON(result)
				},
			},
		},
	}
}

func complianceRefFromCmd(cmd *cli.Command) (velocity.ComplianceResourceRef, error) {
	typ := velocity.ComplianceResourceType(cmd.String("type"))
	ref := velocity.ComplianceResourceRef{Type: typ}
	switch typ {
	case velocity.ComplianceResourceKV:
		ref.Path = cmd.String("path")
	case velocity.ComplianceResourceObject:
		ref.Path = cmd.String("path")
	case velocity.ComplianceResourceBucket:
		ref.Bucket = cmd.String("bucket")
	case velocity.ComplianceResourceFolder:
		ref.Path = cmd.String("path")
	case velocity.ComplianceResourceSecret:
		ref.SecretName = cmd.String("name")
	case velocity.ComplianceResourceSecretVersion:
		ref.SecretName = cmd.String("name")
		ref.SecretVersion = cmd.String("version")
	case velocity.ComplianceResourceSQLSchema:
		ref.SQLSchema = cmd.String("schema")
	case velocity.ComplianceResourceSQLTable:
		ref.SQLSchema = cmd.String("schema")
		ref.SQLTable = cmd.String("table")
	case velocity.ComplianceResourceSQLColumn:
		ref.SQLSchema = cmd.String("schema")
		ref.SQLTable = cmd.String("table")
		ref.SQLColumn = cmd.String("column")
	case velocity.ComplianceResourceSQLRow:
		ref.SQLSchema = cmd.String("schema")
		ref.SQLTable = cmd.String("table")
		ref.SQLRowKey = cmd.String("row")
	default:
		return ref, fmt.Errorf("--type is required and must be one of kv, object, bucket, folder, secret, secret_version, sql_schema, sql_table, sql_column, sql_row")
	}
	if ref.CanonicalID() == "" {
		return ref, fmt.Errorf("missing resource flags for type %s", typ)
	}
	return ref, nil
}

func parseComplianceFrameworks(raw string) ([]compliance.Framework, error) {
	if raw == "" {
		return nil, fmt.Errorf("--framework is required")
	}
	parts := strings.Split(raw, ",")
	frameworks := make([]compliance.Framework, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		switch strings.ToUpper(part) {
		case "HIPAA":
			frameworks = append(frameworks, compliance.FrameworkHIPAA)
		case "GDPR":
			frameworks = append(frameworks, compliance.FrameworkGDPR)
		case "NIST", "NIST_800_53":
			frameworks = append(frameworks, compliance.FrameworkNIST)
		case "FIPS", "FIPS_140_2":
			frameworks = append(frameworks, compliance.FrameworkFIPS)
		case "PCI", "PCI_DSS":
			frameworks = append(frameworks, compliance.FrameworkPCIDSS)
		case "SOC2", "SOC2_TYPE2":
			frameworks = append(frameworks, compliance.FrameworkSOC2)
		case "ISO27001", "ISO_27001":
			frameworks = append(frameworks, compliance.FrameworkISO27001)
		default:
			return nil, fmt.Errorf("unknown framework: %s", part)
		}
	}
	return frameworks, nil
}

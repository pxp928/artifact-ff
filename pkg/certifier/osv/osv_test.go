package osv

import (
	"context"
	"testing"

	"github.com/guacsec/guac/pkg/assembler/graphdb"
	"github.com/guacsec/guac/pkg/handler/processor"
)

func TestOSVCertifier_CertifyVulns(t *testing.T) {

	ctx := context.Background()
	authToken := graphdb.CreateAuthTokenWithUsernameAndPassword("neo4j", "s3cr3t", "neo4j")
	client, err := graphdb.NewGraphClient("neo4j://localhost:7687", authToken)
	var docChannel chan<- *processor.Document
	if err != nil {
		t.Fatal(err)
	}
	o := &OSVCertifier{}
	o.CertifyVulns(ctx, client, docChannel)
	type args struct {
		ctx        context.Context
		client     graphdb.Client
		docChannel chan<- *processor.Document
	}
	tests := []struct {
		name    string
		o       *OSVCertifier
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &OSVCertifier{}
			if err := o.CertifyVulns(ctx, client, tt.args.docChannel); (err != nil) != tt.wantErr {
				t.Errorf("OSVCertifier.CertifyVulns() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

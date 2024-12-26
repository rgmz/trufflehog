package decoders

import (
	"testing"

	"github.com/kylelemons/godebug/pretty"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestUrlDecoder_FromChunk(t *testing.T) {
	tests := []struct {
		name    string
		chunk   *sources.Chunk
		want    *sources.Chunk
		wantErr bool
	}{
		// Valid
		{
			name: "uppercase",
			chunk: &sources.Chunk{
				Data: []byte("aws_session_token=FwoGZXIvYXdzED0aDNHw4GhQvSFSCn8vUCK6Af%2BKK2QGsRbN5F22xJvXyNyYoAzxTkPYrSgvvuL7%2F17tyBa5LMeHWSKV%2F9E3ON2vRSLIz0iFfeEE5cj4zmbqpw%2F5LAiDiptTvbQQKmzCE4Pt05khFcsTmwsju9ibR5Mx2oJKdHHQXCsqk0XjvugSuu%2BKbU0wigO2oSXvu1dguNg%2Bj6RTdxGAS7Uoih2WZR4ZlJCdcFNOivhf%2FkWs18mMRQ43r47GWsV9Z3vlTaMimHLWuBMldPgBcJV2iCiWrpnwBTIt2Dfkgvi8Bs7OcInotWE751K48QJnzcwPMKjsNKBE0tf1kGI9JArO8x%2BaDQJX%3D%3D"),
			},
			want: &sources.Chunk{
				Data: []byte("aws_session_token=FwoGZXIvYXdzED0aDNHw4GhQvSFSCn8vUCK6Af+KK2QGsRbN5F22xJvXyNyYoAzxTkPYrSgvvuL7/17tyBa5LMeHWSKV/9E3ON2vRSLIz0iFfeEE5cj4zmbqpw/5LAiDiptTvbQQKmzCE4Pt05khFcsTmwsju9ibR5Mx2oJKdHHQXCsqk0XjvugSuu+KbU0wigO2oSXvu1dguNg+j6RTdxGAS7Uoih2WZR4ZlJCdcFNOivhf/kWs18mMRQ43r47GWsV9Z3vlTaMimHLWuBMldPgBcJV2iCiWrpnwBTIt2Dfkgvi8Bs7OcInotWE751K48QJnzcwPMKjsNKBE0tf1kGI9JArO8x+aDQJX=="),
			},
		},
		{
			name: "lowercase",
			chunk: &sources.Chunk{
				Data: []byte("https://r2.cloudflarestorage.com/codegeex/codegeex_13b.tar.gz.0?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=b279482b3a1b5758740371cde86a9b62%2f20230112%2fus-east-1%2fs3%2faws4_request&X-Amz-Date=20230112T035544Z&X-Amz-Expires=259200&X-Amz-Signature=eaeb7b40bc57c63bbe33991620240e5bdb4bb97f51bc382b32a1a699a47a94ff&X-Amz-SignedHeaders=host\n"),
			},
			want: &sources.Chunk{
				Data: []byte("https://r2.cloudflarestorage.com/codegeex/codegeex_13b.tar.gz.0?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=b279482b3a1b5758740371cde86a9b62/20230112/us-east-1/s3/aws4_request&X-Amz-Date=20230112T035544Z&X-Amz-Expires=259200&X-Amz-Signature=eaeb7b40bc57c63bbe33991620240e5bdb4bb97f51bc382b32a1a699a47a94ff&X-Amz-SignedHeaders=host\n"),
			},
		},

		// Invalid
		{
			name: "no escaped",
			chunk: &sources.Chunk{
				Data: []byte(`-//npm.fontawesome.com/:_authToken=%YOUR_TOKEN%`),
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Percent{}
			got := d.FromChunk(context.Background(), tt.chunk)
			if tt.want != nil {
				if got == nil {
					t.Fatal("got nil, did not want nil")
				}
				if diff := pretty.Compare(string(tt.want.Data), string(got.Data)); diff != "" {
					t.Errorf("UrlDecoder.FromChunk() %s diff: (-want +got)\n%s", tt.name, diff)
				}
			} else {
				if got != nil {
					t.Error("Expected nil chunk")
				}
			}
		})
	}
}

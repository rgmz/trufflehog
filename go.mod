module github.com/trufflesecurity/trufflehog/v3

go 1.23.1

toolchain go1.24.4

replace github.com/jpillora/overseer => github.com/trufflesecurity/overseer v1.2.8

// Coinbase archived this library and it has some vulnerable dependencies so we've forked.
replace github.com/coinbase/waas-client-library-go => github.com/trufflesecurity/waas-client-library-go v1.0.9

require (
	cloud.google.com/go/secretmanager v1.14.7
	cloud.google.com/go/storage v1.50.0
	github.com/BobuSumisu/aho-corasick v1.0.3
	github.com/TheZeroSlave/zapsentry v1.23.0
	github.com/alecthomas/kingpin/v2 v2.4.0
	github.com/avast/apkparser v0.0.0-20250530053210-166ba1767cb9
	github.com/aws/aws-sdk-go-v2 v1.36.4
	github.com/aws/aws-sdk-go-v2/config v1.29.16
	github.com/aws/aws-sdk-go-v2/credentials v1.17.69
	github.com/aws/aws-sdk-go-v2/feature/s3/manager v1.17.79
	github.com/aws/aws-sdk-go-v2/service/s3 v1.80.2
	github.com/aws/aws-sdk-go-v2/service/sns v1.34.6
	github.com/aws/aws-sdk-go-v2/service/sts v1.33.21
	github.com/aws/smithy-go v1.22.3
	github.com/bill-rich/go-syslog v0.0.0-20220413021637-49edb52a574c
	github.com/bitfinexcom/bitfinex-api-go v0.0.0-20210608095005-9e0b26f200fb
	github.com/bradleyfalzon/ghinstallation/v2 v2.14.0
	github.com/brianvoe/gofakeit/v7 v7.2.1
	github.com/coinbase/waas-client-library-go v1.0.8
	github.com/couchbase/gocb/v2 v2.10.0
	github.com/crewjam/rfc5424 v0.1.0
	github.com/csnewman/dextk v0.3.0
	github.com/dustin/go-humanize v1.0.1
	github.com/elastic/go-elasticsearch/v8 v8.17.1
	github.com/envoyproxy/protoc-gen-validate v1.2.1
	github.com/fatih/color v1.18.0
	github.com/felixge/fgprof v0.9.5
	github.com/gabriel-vasile/mimetype v1.4.9
	github.com/getsentry/sentry-go v0.32.0
	github.com/go-errors/errors v1.5.1
	github.com/go-git/go-git/v5 v5.13.2
	github.com/go-ldap/ldap/v3 v3.4.11
	github.com/go-logr/logr v1.4.3
	github.com/go-logr/zapr v1.3.0
	github.com/go-redis/redis v6.15.9+incompatible
	github.com/go-sql-driver/mysql v1.8.1
	github.com/gobwas/glob v0.2.3
	github.com/golang-jwt/jwt/v5 v5.2.2
	github.com/google/go-cmp v0.7.0
	github.com/google/go-containerregistry v0.20.3
	github.com/google/go-github/v67 v67.0.0
	github.com/google/uuid v1.6.0
	github.com/googleapis/gax-go/v2 v2.14.2
	github.com/hashicorp/go-retryablehttp v0.7.7
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/jedib0t/go-pretty/v6 v6.6.7
	github.com/jlaffaye/ftp v0.2.0
	github.com/joho/godotenv v1.5.1
	github.com/jpillora/overseer v1.1.6
	github.com/k0kubun/go-ansi v0.0.0-20180517002512-3bf9e2903213
	github.com/klauspost/pgzip v1.2.6
	github.com/kylelemons/godebug v1.1.0
	github.com/lib/pq v1.10.9
	github.com/marusama/semaphore/v2 v2.5.0
	github.com/mholt/archives v0.0.0-20241216060121-23e0af8fe73d
	github.com/microsoft/go-mssqldb v1.8.2
	github.com/mitchellh/go-ps v1.0.0
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/paulbellamy/ratecounter v0.2.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.20.5
	github.com/rabbitmq/amqp091-go v1.10.0
	github.com/repeale/fp-go v0.11.1
	github.com/sassoftware/go-rpmutils v0.4.0
	github.com/schollz/progressbar/v3 v3.17.1
	github.com/sendgrid/sendgrid-go v3.16.0+incompatible
	github.com/sergi/go-diff v1.3.2-0.20230802210424-5b0b94c5c0d3
	github.com/shuheiktgw/go-travis v0.3.1
	github.com/stretchr/testify v1.10.0
	github.com/tailscale/depaware v0.0.0-20250112153213-b748de04d81b
	github.com/testcontainers/testcontainers-go v0.34.0
	github.com/testcontainers/testcontainers-go/modules/elasticsearch v0.34.0
	github.com/testcontainers/testcontainers-go/modules/mongodb v0.34.0
	github.com/testcontainers/testcontainers-go/modules/mssql v0.34.0
	github.com/testcontainers/testcontainers-go/modules/mysql v0.34.0
	github.com/testcontainers/testcontainers-go/modules/postgres v0.34.0
	github.com/trufflesecurity/disk-buffer-reader v0.2.1
	github.com/wasilibs/go-re2 v1.9.0
	github.com/xo/dburl v0.23.7
	gitlab.com/gitlab-org/api/client-go v0.127.0
	go.mongodb.org/mongo-driver v1.17.3
	go.uber.org/automaxprocs v1.6.0
	go.uber.org/mock v0.5.1
	go.uber.org/zap v1.27.0
	golang.org/x/crypto v0.37.0
	golang.org/x/exp v0.0.0-20240719175910-8a7402abbf56
	golang.org/x/net v0.39.0
	golang.org/x/oauth2 v0.30.0
	golang.org/x/sync v0.14.0
	golang.org/x/text v0.24.0
	golang.org/x/time v0.11.0
	google.golang.org/api v0.232.0
	google.golang.org/protobuf v1.36.6
	gopkg.in/h2non/gock.v1 v1.1.2
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.1
	pault.ag/go/debian v0.18.0
	pgregory.net/rapid v1.1.0
	sigs.k8s.io/yaml v1.4.0
)

require (
	cel.dev/expr v0.20.0 // indirect
	cloud.google.com/go v0.120.0 // indirect
	cloud.google.com/go/auth v0.16.1 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.6.0 // indirect
	cloud.google.com/go/iam v1.5.2 // indirect
	cloud.google.com/go/longrunning v0.6.7 // indirect
	cloud.google.com/go/monitoring v1.24.2 // indirect
	dario.cat/mergo v1.0.0 // indirect
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/AdaLogics/go-fuzz-headers v0.0.0-20230811130428-ced1acdcaa24 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20210617225240-d185dfc1b5a1 // indirect
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.3.2 // indirect
	github.com/DataDog/zstd v1.5.5 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp v1.26.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric v0.50.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/internal/resourcemapping v0.50.0 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/ProtonMail/go-crypto v1.1.5 // indirect
	github.com/STARRY-S/zip v0.2.1 // indirect
	github.com/alecthomas/units v0.0.0-20211218093645-b94a6e3cc137 // indirect
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.6.10 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.31 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.35 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.35 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.3.35 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.7.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.16 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.18.16 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.25.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.30.2 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bodgit/plumbing v1.3.0 // indirect
	github.com/bodgit/sevenzip v1.6.0 // indirect
	github.com/bodgit/windows v1.0.1 // indirect
	github.com/cenkalti/backoff/v4 v4.2.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudflare/circl v1.3.8 // indirect
	github.com/cncf/xds/go v0.0.0-20250121191232-2f005788dc42 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/platforms v0.2.1 // indirect
	github.com/containerd/stargz-snapshotter/estargz v0.16.3 // indirect
	github.com/couchbase/gocbcore/v10 v10.7.0 // indirect
	github.com/couchbase/gocbcoreps v0.1.3 // indirect
	github.com/couchbase/goprotostellar v1.0.2 // indirect
	github.com/couchbaselabs/gocbconnstr/v2 v2.0.0-20240607131231-fb385523de28 // indirect
	github.com/cpuguy83/dockercfg v0.3.2 // indirect
	github.com/cyphar/filepath-securejoin v0.3.6 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/cli v27.5.0+incompatible // indirect
	github.com/docker/distribution v2.8.3+incompatible // indirect
	github.com/docker/docker v27.5.0+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.8.2 // indirect
	github.com/docker/go-connections v0.5.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/dsnet/compress v0.0.2-0.20230904184137-39efe44ab707 // indirect
	github.com/elastic/elastic-transport-go/v8 v8.6.1 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/envoyproxy/go-control-plane/envoy v1.32.4 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8-0.20250403174932-29230038a667 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-git/go-billy/v5 v5.6.2 // indirect
	github.com/go-jose/go-jose/v4 v4.0.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/gofrs/flock v0.12.1 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.1 // indirect
	github.com/golang-sql/civil v0.0.0-20220223132316-b832511892a9 // indirect
	github.com/golang-sql/sqlexp v0.1.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/go-github/v69 v69.0.0 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/pprof v0.0.0-20240227163752-401108e1b7e7 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.6 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.4.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.16.0 // indirect
	github.com/h2non/parth v0.0.0-20190131123155-b4df798d6542 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/jpillora/s3 v1.1.4 // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/kjk/lzma v0.0.0-20161016003348-3fd93898850d // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/mitchellh/colorstring v0.0.0-20190213212951-d06e56a500db // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/patternmatcher v0.6.0 // indirect
	github.com/moby/sys/sequential v0.5.0 // indirect
	github.com/moby/sys/user v0.1.0 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/moby/term v0.5.0 // indirect
	github.com/montanaflynn/stats v0.7.1 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/nwaples/rardecode/v2 v2.0.0-beta.4.0.20241112120701-034e449c6e78 // indirect
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0 // indirect
	github.com/pierrec/lz4/v4 v4.1.21 // indirect
	github.com/pjbgf/sha1cd v0.3.2 // indirect
	github.com/pkg/diff v0.0.0-20200914180035-5b29258ca4f7 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.55.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/sendgrid/rest v2.6.9+incompatible // indirect
	github.com/shirou/gopsutil/v3 v3.23.12 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/skeema/knownhosts v1.3.0 // indirect
	github.com/sorairolake/lzip-go v0.3.5 // indirect
	github.com/spiffe/go-spiffe/v2 v2.5.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/tetratelabs/wazero v1.9.0 // indirect
	github.com/therootcompany/xz v1.0.1 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/trufflesecurity/touchfile v0.1.1 // indirect
	github.com/ulikunitz/xz v0.5.12 // indirect
	github.com/vbatts/tar-split v0.11.6 // indirect
	github.com/wasilibs/wazero-helpers v0.0.0-20240620070341-3dff1577cd52 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.1.2 // indirect
	github.com/xdg-go/stringprep v1.0.4 // indirect
	github.com/xhit/go-str2duration/v2 v2.1.0 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	github.com/yusufpapurcu/wmi v1.2.3 // indirect
	github.com/zeebo/errs v1.4.0 // indirect
	go.einride.tech/aip v0.60.0 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/contrib/detectors/gcp v1.34.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.60.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.60.0 // indirect
	go.opentelemetry.io/otel v1.35.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.19.0 // indirect
	go.opentelemetry.io/otel/metric v1.35.0 // indirect
	go.opentelemetry.io/otel/sdk v1.35.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.35.0 // indirect
	go.opentelemetry.io/otel/trace v1.35.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go4.org v0.0.0-20230225012048-214862532bf5 // indirect
	golang.org/x/mod v0.22.0 // indirect
	golang.org/x/sys v0.32.0 // indirect
	golang.org/x/term v0.31.0 // indirect
	golang.org/x/tools v0.29.0 // indirect
	google.golang.org/genproto v0.0.0-20250505200425-f936aa4a68b2 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250505200425-f936aa4a68b2 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250505200425-f936aa4a68b2 // indirect
	google.golang.org/grpc v1.72.0 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	pault.ag/go/topsort v0.1.1 // indirect
)

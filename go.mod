module github.com/netwatcherio/netwatcher-agent

go 1.25.4

require (
	github.com/elastic/go-sysinfo v1.11.1
	github.com/jackpal/gateway v1.0.13
	github.com/joho/godotenv v1.5.1
	github.com/kataras/iris/v12 v12.2.8
	github.com/kataras/neffos v0.0.22
	github.com/nxtrace/NTrace-core v1.3.6
	github.com/prometheus-community/pro-bing v0.3.0
	github.com/showwin/speedtest-go v1.7.7
	github.com/sirupsen/logrus v1.9.3
	go.mongodb.org/mongo-driver v1.17.6
	golang.org/x/sync v0.18.0
	golang.org/x/sys v0.38.0
)

require (
	github.com/Shopify/goreferrer v0.0.0-20220729165902-8cddb4f5de06 // indirect
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/aymerick/douceur v0.2.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/elastic/go-windows v1.0.1 // indirect
	github.com/fatih/color v1.18.0 // indirect
	github.com/fatih/structs v1.1.0 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.4.0 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/gobwas/ws v1.3.1 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/gomarkdown/markdown v0.0.0-20231115200524-a660076da3fd // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/google/uuid v1.4.0 // indirect
	github.com/gorilla/css v1.0.1 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/iris-contrib/go.uuid v2.0.0+incompatible // indirect
	github.com/iris-contrib/schema v0.0.6 // indirect
	github.com/joeshaw/multierror v0.0.0-20140124173710-69b34d4ec901 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/jsdelivr/globalping-cli v1.5.1 // indirect
	github.com/kataras/golog v0.1.11 // indirect
	github.com/kataras/pio v0.0.13 // indirect
	github.com/klauspost/compress v1.17.3 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mediocregopher/radix/v3 v3.8.1 // indirect
	github.com/microcosm-cc/bluemonday v1.0.26 // indirect
	github.com/nats-io/nats.go v1.34.0 // indirect
	github.com/nats-io/nkeys v0.4.7 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/oschwald/maxminddb-golang v1.13.1 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	github.com/sagikazarmark/locafero v0.12.0 // indirect
	github.com/shirou/gopsutil/v3 v3.24.5 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/spf13/viper v1.21.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/tdewolff/minify/v2 v2.20.7 // indirect
	github.com/tdewolff/parse/v2 v2.7.5 // indirect
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/match v1.2.0 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tsosunchia/powclient v0.2.0 // indirect
	github.com/vmihailenco/msgpack/v5 v5.4.1 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	github.com/xjasonlyu/windivert-go v0.0.0-20201010013527-4239d0afa76f // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/exp v0.0.0-20241217172543-b2144cdd0a67 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/text v0.31.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	golang.org/x/xerrors v0.0.0-20231012003039-104605ab7028 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	howett.net/plist v1.0.0 // indirect
)

// Use local NTrace-core with Go 1.24 darwin compatibility fix
replace github.com/nxtrace/NTrace-core => ./lib/NTrace-core

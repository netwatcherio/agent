package workers

import (
	"encoding/json"
	"github.com/netwatcherio/netwatcher-agent/probes"
	"github.com/netwatcherio/netwatcher-agent/web"
	log "github.com/sirupsen/logrus"
)

func ProbeDataWorker(wsH *web.WSClient, ch chan probes.ProbeData) {
	go func(cn *web.WSClient, c chan probes.ProbeData) {
		for p := range ch {
			marshal, err := json.Marshal(p)
			log.Warn(string(marshal))
			if err != nil {
				return
			}

			wsH.WsConn.Emit("probe_post", marshal)
		}
	}(wsH, ch)
}

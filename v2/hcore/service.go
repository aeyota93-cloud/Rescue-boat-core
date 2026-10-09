package hcore

import (
	"context"

	"github.com/hiddify/hiddify-core/v2/rescuestats"
	box "github.com/sagernet/sing-box"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/experimental/clashapi"
	"github.com/sagernet/sing-box/experimental/clashapi/trafficontrol"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

func NewService(ctx context.Context, options option.Options) (*daemon.StartedService, error) {
	return newService(ctx, options, nil)
}

// newService — то же, но со сборщиком статистики (nil — без него).
func newService(ctx context.Context, options option.Options, stats *rescuestats.Collector) (*daemon.StartedService, error) {
	extraServices := []adapter.LifecycleService{&hiddifyMainServiceManager{}}
	if stats != nil {
		extraServices = append(extraServices, stats)
	}

	// ctx = filemanager.WithDefault(ctx, sWorkingPath, sTempPath, sUserID, sGroupID)
	logInterface := LogInterface{}
	bopts := daemon.ServiceOptions{
		Context:     ctx,
		Debug:       static.debug,
		LogMaxLines: 100,
		// Options:           *options,
		Handler:       &logInterface,
		ExtraServices: extraServices,
	}
	err := libbox.CheckConfigOptions(&options)
	if err != nil {
		return nil, err
	}
	instance := daemon.NewStartedService(bopts)
	if stats != nil {
		stats.Bind(instance)
	}

	// for i := 0; i < 10; i++ {
	// 	if hutils.IsPortInUse(options.Inbounds[0].SocksOptions.ListenPort) {
	// 		<-time.After(100 * time.Millisecond)
	// 	}
	// }

	if err := instance.StartOrReloadServiceOptions(options); err != nil {
		return nil, err
	}

	// instance.GetInstance().AddPostService("hiddifyMainServiceManager", &hiddifyMainServiceManager{})

	// if err := startCommandServer(instance); err != nil {
	// 	return errorWrapper(MessageType_START_COMMAND_SERVER, err)
	// }

	return instance, nil
}

func (h *HiddifyInstance) UrlTestHistory() *urltest.HistoryStorage {

	ins := h.Instance()
	if ins == nil {
		return nil
	}
	return ins.UrlTestHistory()
}

func (h *HiddifyInstance) Box() *box.Box {
	ins := h.Instance()
	if ins == nil {
		return nil
	}
	return ins.Box()
}

func (h *HiddifyInstance) Instance() *daemon.Instance {
	ss := h.StartedService
	if ss == nil {
		return nil
	}
	return ss.Instance()

}

func (h *HiddifyInstance) Context() context.Context {
	ins := h.Instance()
	if ins == nil {
		return nil
	}
	return ins.Context()
}

func (h *HiddifyInstance) TrafficManager() *trafficontrol.Manager {
	if ins := h.Instance(); ins != nil {
		if s := ins.ClashServer(); s != nil {
			return s.(*clashapi.Server).TrafficManager()
		}
	}
	return nil
}

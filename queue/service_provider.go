package queue

import (
	"github.com/goravel/framework/contracts/console"
	"github.com/goravel/framework/contracts/database/orm"
	"github.com/goravel/framework/contracts/foundation"
	queueConsole "github.com/goravel/framework/queue/console"
)

const Binding = "goravel.queue"

var (
	App       foundation.Application
	OrmFacade orm.Orm
)

type ServiceProvider struct {
}

func (receiver *ServiceProvider) Register(app foundation.Application) {
	App = app

	app.Singleton(Binding, func(app foundation.Application) (any, error) {
		return NewApplication(app.MakeConfig(), app.MakeLog()), nil
	})
}

func (receiver *ServiceProvider) Boot(app foundation.Application) {
	OrmFacade = app.MakeOrm()

	receiver.registerCommands(app)
}

func (receiver *ServiceProvider) registerCommands(app foundation.Application) {
	app.MakeArtisan().Register([]console.Command{
		&queueConsole.JobMakeCommand{},
	})
}

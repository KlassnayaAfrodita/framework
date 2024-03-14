// Code generated by mockery v2.42.1. DO NOT EDIT.

package mocks

import (
	auth "github.com/goravel/framework/contracts/auth"
	access "github.com/goravel/framework/contracts/auth/access"

	cache "github.com/goravel/framework/contracts/cache"

	config "github.com/goravel/framework/contracts/config"

	console "github.com/goravel/framework/contracts/console"

	context "context"

	crypt "github.com/goravel/framework/contracts/crypt"

	event "github.com/goravel/framework/contracts/event"

	filesystem "github.com/goravel/framework/contracts/filesystem"

	foundation "github.com/goravel/framework/contracts/foundation"

	grpc "github.com/goravel/framework/contracts/grpc"

	hash "github.com/goravel/framework/contracts/hash"

	http "github.com/goravel/framework/contracts/http"

	log "github.com/goravel/framework/contracts/log"

	mail "github.com/goravel/framework/contracts/mail"

	mock "github.com/stretchr/testify/mock"

	orm "github.com/goravel/framework/contracts/database/orm"

	queue "github.com/goravel/framework/contracts/queue"

	route "github.com/goravel/framework/contracts/route"

	schedule "github.com/goravel/framework/contracts/schedule"

	schema "github.com/goravel/framework/contracts/database/schema"

	seeder "github.com/goravel/framework/contracts/database/seeder"

	session "github.com/goravel/framework/contracts/session"

	testing "github.com/goravel/framework/contracts/testing"

	translation "github.com/goravel/framework/contracts/translation"

	validation "github.com/goravel/framework/contracts/validation"
)

// Container is an autogenerated mock type for the Container type
type Container struct {
	mock.Mock
}

type Container_Expecter struct {
	mock *mock.Mock
}

func (_m *Container) EXPECT() *Container_Expecter {
	return &Container_Expecter{mock: &_m.Mock}
}

// Bind provides a mock function with given fields: key, callback
func (_m *Container) Bind(key interface{}, callback func(foundation.Application) (interface{}, error)) {
	_m.Called(key, callback)
}

// Container_Bind_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Bind'
type Container_Bind_Call struct {
	*mock.Call
}

// Bind is a helper method to define mock.On call
//   - key interface{}
//   - callback func(foundation.Application)(interface{} , error)
func (_e *Container_Expecter) Bind(key interface{}, callback interface{}) *Container_Bind_Call {
	return &Container_Bind_Call{Call: _e.mock.On("Bind", key, callback)}
}

func (_c *Container_Bind_Call) Run(run func(key interface{}, callback func(foundation.Application) (interface{}, error))) *Container_Bind_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(interface{}), args[1].(func(foundation.Application) (interface{}, error)))
	})
	return _c
}

func (_c *Container_Bind_Call) Return() *Container_Bind_Call {
	_c.Call.Return()
	return _c
}

func (_c *Container_Bind_Call) RunAndReturn(run func(interface{}, func(foundation.Application) (interface{}, error))) *Container_Bind_Call {
	_c.Call.Return(run)
	return _c
}

// BindWith provides a mock function with given fields: key, callback
func (_m *Container) BindWith(key interface{}, callback func(foundation.Application, map[string]interface{}) (interface{}, error)) {
	_m.Called(key, callback)
}

// Container_BindWith_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'BindWith'
type Container_BindWith_Call struct {
	*mock.Call
}

// BindWith is a helper method to define mock.On call
//   - key interface{}
//   - callback func(foundation.Application , map[string]interface{})(interface{} , error)
func (_e *Container_Expecter) BindWith(key interface{}, callback interface{}) *Container_BindWith_Call {
	return &Container_BindWith_Call{Call: _e.mock.On("BindWith", key, callback)}
}

func (_c *Container_BindWith_Call) Run(run func(key interface{}, callback func(foundation.Application, map[string]interface{}) (interface{}, error))) *Container_BindWith_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(interface{}), args[1].(func(foundation.Application, map[string]interface{}) (interface{}, error)))
	})
	return _c
}

func (_c *Container_BindWith_Call) Return() *Container_BindWith_Call {
	_c.Call.Return()
	return _c
}

func (_c *Container_BindWith_Call) RunAndReturn(run func(interface{}, func(foundation.Application, map[string]interface{}) (interface{}, error))) *Container_BindWith_Call {
	_c.Call.Return(run)
	return _c
}

// Instance provides a mock function with given fields: key, instance
func (_m *Container) Instance(key interface{}, instance interface{}) {
	_m.Called(key, instance)
}

// Container_Instance_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Instance'
type Container_Instance_Call struct {
	*mock.Call
}

// Instance is a helper method to define mock.On call
//   - key interface{}
//   - instance interface{}
func (_e *Container_Expecter) Instance(key interface{}, instance interface{}) *Container_Instance_Call {
	return &Container_Instance_Call{Call: _e.mock.On("Instance", key, instance)}
}

func (_c *Container_Instance_Call) Run(run func(key interface{}, instance interface{})) *Container_Instance_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(interface{}), args[1].(interface{}))
	})
	return _c
}

func (_c *Container_Instance_Call) Return() *Container_Instance_Call {
	_c.Call.Return()
	return _c
}

func (_c *Container_Instance_Call) RunAndReturn(run func(interface{}, interface{})) *Container_Instance_Call {
	_c.Call.Return(run)
	return _c
}

// Make provides a mock function with given fields: key
func (_m *Container) Make(key interface{}) (interface{}, error) {
	ret := _m.Called(key)

	if len(ret) == 0 {
		panic("no return value specified for Make")
	}

	var r0 interface{}
	var r1 error
	if rf, ok := ret.Get(0).(func(interface{}) (interface{}, error)); ok {
		return rf(key)
	}
	if rf, ok := ret.Get(0).(func(interface{}) interface{}); ok {
		r0 = rf(key)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(interface{})
		}
	}

	if rf, ok := ret.Get(1).(func(interface{}) error); ok {
		r1 = rf(key)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Container_Make_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Make'
type Container_Make_Call struct {
	*mock.Call
}

// Make is a helper method to define mock.On call
//   - key interface{}
func (_e *Container_Expecter) Make(key interface{}) *Container_Make_Call {
	return &Container_Make_Call{Call: _e.mock.On("Make", key)}
}

func (_c *Container_Make_Call) Run(run func(key interface{})) *Container_Make_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(interface{}))
	})
	return _c
}

func (_c *Container_Make_Call) Return(_a0 interface{}, _a1 error) *Container_Make_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Container_Make_Call) RunAndReturn(run func(interface{}) (interface{}, error)) *Container_Make_Call {
	_c.Call.Return(run)
	return _c
}

// MakeArtisan provides a mock function with given fields:
func (_m *Container) MakeArtisan() console.Artisan {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for MakeArtisan")
	}

	var r0 console.Artisan
	if rf, ok := ret.Get(0).(func() console.Artisan); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(console.Artisan)
		}
	}

	return r0
}

// Container_MakeArtisan_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MakeArtisan'
type Container_MakeArtisan_Call struct {
	*mock.Call
}

// MakeArtisan is a helper method to define mock.On call
func (_e *Container_Expecter) MakeArtisan() *Container_MakeArtisan_Call {
	return &Container_MakeArtisan_Call{Call: _e.mock.On("MakeArtisan")}
}

func (_c *Container_MakeArtisan_Call) Run(run func()) *Container_MakeArtisan_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Container_MakeArtisan_Call) Return(_a0 console.Artisan) *Container_MakeArtisan_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Container_MakeArtisan_Call) RunAndReturn(run func() console.Artisan) *Container_MakeArtisan_Call {
	_c.Call.Return(run)
	return _c
}

// MakeAuth provides a mock function with given fields: ctx
func (_m *Container) MakeAuth(ctx http.Context) auth.Auth {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for MakeAuth")
	}

	var r0 auth.Auth
	if rf, ok := ret.Get(0).(func(http.Context) auth.Auth); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(auth.Auth)
		}
	}

	return r0
}

// Container_MakeAuth_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MakeAuth'
type Container_MakeAuth_Call struct {
	*mock.Call
}

// MakeAuth is a helper method to define mock.On call
//   - ctx http.Context
func (_e *Container_Expecter) MakeAuth(ctx interface{}) *Container_MakeAuth_Call {
	return &Container_MakeAuth_Call{Call: _e.mock.On("MakeAuth", ctx)}
}

func (_c *Container_MakeAuth_Call) Run(run func(ctx http.Context)) *Container_MakeAuth_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(http.Context))
	})
	return _c
}

func (_c *Container_MakeAuth_Call) Return(_a0 auth.Auth) *Container_MakeAuth_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Container_MakeAuth_Call) RunAndReturn(run func(http.Context) auth.Auth) *Container_MakeAuth_Call {
	_c.Call.Return(run)
	return _c
}

// MakeCache provides a mock function with given fields:
func (_m *Container) MakeCache() cache.Cache {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for MakeCache")
	}

	var r0 cache.Cache
	if rf, ok := ret.Get(0).(func() cache.Cache); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(cache.Cache)
		}
	}

	return r0
}

// Container_MakeCache_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MakeCache'
type Container_MakeCache_Call struct {
	*mock.Call
}

// MakeCache is a helper method to define mock.On call
func (_e *Container_Expecter) MakeCache() *Container_MakeCache_Call {
	return &Container_MakeCache_Call{Call: _e.mock.On("MakeCache")}
}

func (_c *Container_MakeCache_Call) Run(run func()) *Container_MakeCache_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Container_MakeCache_Call) Return(_a0 cache.Cache) *Container_MakeCache_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Container_MakeCache_Call) RunAndReturn(run func() cache.Cache) *Container_MakeCache_Call {
	_c.Call.Return(run)
	return _c
}

// MakeConfig provides a mock function with given fields:
func (_m *Container) MakeConfig() config.Config {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for MakeConfig")
	}

	var r0 config.Config
	if rf, ok := ret.Get(0).(func() config.Config); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(config.Config)
		}
	}

	return r0
}

// Container_MakeConfig_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MakeConfig'
type Container_MakeConfig_Call struct {
	*mock.Call
}

// MakeConfig is a helper method to define mock.On call
func (_e *Container_Expecter) MakeConfig() *Container_MakeConfig_Call {
	return &Container_MakeConfig_Call{Call: _e.mock.On("MakeConfig")}
}

func (_c *Container_MakeConfig_Call) Run(run func()) *Container_MakeConfig_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Container_MakeConfig_Call) Return(_a0 config.Config) *Container_MakeConfig_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Container_MakeConfig_Call) RunAndReturn(run func() config.Config) *Container_MakeConfig_Call {
	_c.Call.Return(run)
	return _c
}

// MakeCrypt provides a mock function with given fields:
func (_m *Container) MakeCrypt() crypt.Crypt {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for MakeCrypt")
	}

	var r0 crypt.Crypt
	if rf, ok := ret.Get(0).(func() crypt.Crypt); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(crypt.Crypt)
		}
	}

	return r0
}

// Container_MakeCrypt_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MakeCrypt'
type Container_MakeCrypt_Call struct {
	*mock.Call
}

// MakeCrypt is a helper method to define mock.On call
func (_e *Container_Expecter) MakeCrypt() *Container_MakeCrypt_Call {
	return &Container_MakeCrypt_Call{Call: _e.mock.On("MakeCrypt")}
}

func (_c *Container_MakeCrypt_Call) Run(run func()) *Container_MakeCrypt_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Container_MakeCrypt_Call) Return(_a0 crypt.Crypt) *Container_MakeCrypt_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Container_MakeCrypt_Call) RunAndReturn(run func() crypt.Crypt) *Container_MakeCrypt_Call {
	_c.Call.Return(run)
	return _c
}

// MakeEvent provides a mock function with given fields:
func (_m *Container) MakeEvent() event.Instance {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for MakeEvent")
	}

	var r0 event.Instance
	if rf, ok := ret.Get(0).(func() event.Instance); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(event.Instance)
		}
	}

	return r0
}

// Container_MakeEvent_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MakeEvent'
type Container_MakeEvent_Call struct {
	*mock.Call
}

// MakeEvent is a helper method to define mock.On call
func (_e *Container_Expecter) MakeEvent() *Container_MakeEvent_Call {
	return &Container_MakeEvent_Call{Call: _e.mock.On("MakeEvent")}
}

func (_c *Container_MakeEvent_Call) Run(run func()) *Container_MakeEvent_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Container_MakeEvent_Call) Return(_a0 event.Instance) *Container_MakeEvent_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Container_MakeEvent_Call) RunAndReturn(run func() event.Instance) *Container_MakeEvent_Call {
	_c.Call.Return(run)
	return _c
}

// MakeGate provides a mock function with given fields:
func (_m *Container) MakeGate() access.Gate {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for MakeGate")
	}

	var r0 access.Gate
	if rf, ok := ret.Get(0).(func() access.Gate); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(access.Gate)
		}
	}

	return r0
}

// Container_MakeGate_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MakeGate'
type Container_MakeGate_Call struct {
	*mock.Call
}

// MakeGate is a helper method to define mock.On call
func (_e *Container_Expecter) MakeGate() *Container_MakeGate_Call {
	return &Container_MakeGate_Call{Call: _e.mock.On("MakeGate")}
}

func (_c *Container_MakeGate_Call) Run(run func()) *Container_MakeGate_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Container_MakeGate_Call) Return(_a0 access.Gate) *Container_MakeGate_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Container_MakeGate_Call) RunAndReturn(run func() access.Gate) *Container_MakeGate_Call {
	_c.Call.Return(run)
	return _c
}

// MakeGrpc provides a mock function with given fields:
func (_m *Container) MakeGrpc() grpc.Grpc {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for MakeGrpc")
	}

	var r0 grpc.Grpc
	if rf, ok := ret.Get(0).(func() grpc.Grpc); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(grpc.Grpc)
		}
	}

	return r0
}

// Container_MakeGrpc_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MakeGrpc'
type Container_MakeGrpc_Call struct {
	*mock.Call
}

// MakeGrpc is a helper method to define mock.On call
func (_e *Container_Expecter) MakeGrpc() *Container_MakeGrpc_Call {
	return &Container_MakeGrpc_Call{Call: _e.mock.On("MakeGrpc")}
}

func (_c *Container_MakeGrpc_Call) Run(run func()) *Container_MakeGrpc_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Container_MakeGrpc_Call) Return(_a0 grpc.Grpc) *Container_MakeGrpc_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Container_MakeGrpc_Call) RunAndReturn(run func() grpc.Grpc) *Container_MakeGrpc_Call {
	_c.Call.Return(run)
	return _c
}

// MakeHash provides a mock function with given fields:
func (_m *Container) MakeHash() hash.Hash {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for MakeHash")
	}

	var r0 hash.Hash
	if rf, ok := ret.Get(0).(func() hash.Hash); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(hash.Hash)
		}
	}

	return r0
}

// Container_MakeHash_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MakeHash'
type Container_MakeHash_Call struct {
	*mock.Call
}

// MakeHash is a helper method to define mock.On call
func (_e *Container_Expecter) MakeHash() *Container_MakeHash_Call {
	return &Container_MakeHash_Call{Call: _e.mock.On("MakeHash")}
}

func (_c *Container_MakeHash_Call) Run(run func()) *Container_MakeHash_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Container_MakeHash_Call) Return(_a0 hash.Hash) *Container_MakeHash_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Container_MakeHash_Call) RunAndReturn(run func() hash.Hash) *Container_MakeHash_Call {
	_c.Call.Return(run)
	return _c
}

// MakeLang provides a mock function with given fields: ctx
func (_m *Container) MakeLang(ctx context.Context) translation.Translator {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for MakeLang")
	}

	var r0 translation.Translator
	if rf, ok := ret.Get(0).(func(context.Context) translation.Translator); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(translation.Translator)
		}
	}

	return r0
}

// Container_MakeLang_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MakeLang'
type Container_MakeLang_Call struct {
	*mock.Call
}

// MakeLang is a helper method to define mock.On call
//   - ctx context.Context
func (_e *Container_Expecter) MakeLang(ctx interface{}) *Container_MakeLang_Call {
	return &Container_MakeLang_Call{Call: _e.mock.On("MakeLang", ctx)}
}

func (_c *Container_MakeLang_Call) Run(run func(ctx context.Context)) *Container_MakeLang_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *Container_MakeLang_Call) Return(_a0 translation.Translator) *Container_MakeLang_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Container_MakeLang_Call) RunAndReturn(run func(context.Context) translation.Translator) *Container_MakeLang_Call {
	_c.Call.Return(run)
	return _c
}

// MakeLog provides a mock function with given fields:
func (_m *Container) MakeLog() log.Log {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for MakeLog")
	}

	var r0 log.Log
	if rf, ok := ret.Get(0).(func() log.Log); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(log.Log)
		}
	}

	return r0
}

// Container_MakeLog_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MakeLog'
type Container_MakeLog_Call struct {
	*mock.Call
}

// MakeLog is a helper method to define mock.On call
func (_e *Container_Expecter) MakeLog() *Container_MakeLog_Call {
	return &Container_MakeLog_Call{Call: _e.mock.On("MakeLog")}
}

func (_c *Container_MakeLog_Call) Run(run func()) *Container_MakeLog_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Container_MakeLog_Call) Return(_a0 log.Log) *Container_MakeLog_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Container_MakeLog_Call) RunAndReturn(run func() log.Log) *Container_MakeLog_Call {
	_c.Call.Return(run)
	return _c
}

// MakeMail provides a mock function with given fields:
func (_m *Container) MakeMail() mail.Mail {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for MakeMail")
	}

	var r0 mail.Mail
	if rf, ok := ret.Get(0).(func() mail.Mail); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(mail.Mail)
		}
	}

	return r0
}

// Container_MakeMail_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MakeMail'
type Container_MakeMail_Call struct {
	*mock.Call
}

// MakeMail is a helper method to define mock.On call
func (_e *Container_Expecter) MakeMail() *Container_MakeMail_Call {
	return &Container_MakeMail_Call{Call: _e.mock.On("MakeMail")}
}

func (_c *Container_MakeMail_Call) Run(run func()) *Container_MakeMail_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Container_MakeMail_Call) Return(_a0 mail.Mail) *Container_MakeMail_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Container_MakeMail_Call) RunAndReturn(run func() mail.Mail) *Container_MakeMail_Call {
	_c.Call.Return(run)
	return _c
}

// MakeOrm provides a mock function with given fields:
func (_m *Container) MakeOrm() orm.Orm {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for MakeOrm")
	}

	var r0 orm.Orm
	if rf, ok := ret.Get(0).(func() orm.Orm); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(orm.Orm)
		}
	}

	return r0
}

// Container_MakeOrm_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MakeOrm'
type Container_MakeOrm_Call struct {
	*mock.Call
}

// MakeOrm is a helper method to define mock.On call
func (_e *Container_Expecter) MakeOrm() *Container_MakeOrm_Call {
	return &Container_MakeOrm_Call{Call: _e.mock.On("MakeOrm")}
}

func (_c *Container_MakeOrm_Call) Run(run func()) *Container_MakeOrm_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Container_MakeOrm_Call) Return(_a0 orm.Orm) *Container_MakeOrm_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Container_MakeOrm_Call) RunAndReturn(run func() orm.Orm) *Container_MakeOrm_Call {
	_c.Call.Return(run)
	return _c
}

// MakeQueue provides a mock function with given fields:
func (_m *Container) MakeQueue() queue.Queue {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for MakeQueue")
	}

	var r0 queue.Queue
	if rf, ok := ret.Get(0).(func() queue.Queue); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(queue.Queue)
		}
	}

	return r0
}

// Container_MakeQueue_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MakeQueue'
type Container_MakeQueue_Call struct {
	*mock.Call
}

// MakeQueue is a helper method to define mock.On call
func (_e *Container_Expecter) MakeQueue() *Container_MakeQueue_Call {
	return &Container_MakeQueue_Call{Call: _e.mock.On("MakeQueue")}
}

func (_c *Container_MakeQueue_Call) Run(run func()) *Container_MakeQueue_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Container_MakeQueue_Call) Return(_a0 queue.Queue) *Container_MakeQueue_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Container_MakeQueue_Call) RunAndReturn(run func() queue.Queue) *Container_MakeQueue_Call {
	_c.Call.Return(run)
	return _c
}

// MakeRateLimiter provides a mock function with given fields:
func (_m *Container) MakeRateLimiter() http.RateLimiter {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for MakeRateLimiter")
	}

	var r0 http.RateLimiter
	if rf, ok := ret.Get(0).(func() http.RateLimiter); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(http.RateLimiter)
		}
	}

	return r0
}

// Container_MakeRateLimiter_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MakeRateLimiter'
type Container_MakeRateLimiter_Call struct {
	*mock.Call
}

// MakeRateLimiter is a helper method to define mock.On call
func (_e *Container_Expecter) MakeRateLimiter() *Container_MakeRateLimiter_Call {
	return &Container_MakeRateLimiter_Call{Call: _e.mock.On("MakeRateLimiter")}
}

func (_c *Container_MakeRateLimiter_Call) Run(run func()) *Container_MakeRateLimiter_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Container_MakeRateLimiter_Call) Return(_a0 http.RateLimiter) *Container_MakeRateLimiter_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Container_MakeRateLimiter_Call) RunAndReturn(run func() http.RateLimiter) *Container_MakeRateLimiter_Call {
	_c.Call.Return(run)
	return _c
}

// MakeRoute provides a mock function with given fields:
func (_m *Container) MakeRoute() route.Route {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for MakeRoute")
	}

	var r0 route.Route
	if rf, ok := ret.Get(0).(func() route.Route); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(route.Route)
		}
	}

	return r0
}

// Container_MakeRoute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MakeRoute'
type Container_MakeRoute_Call struct {
	*mock.Call
}

// MakeRoute is a helper method to define mock.On call
func (_e *Container_Expecter) MakeRoute() *Container_MakeRoute_Call {
	return &Container_MakeRoute_Call{Call: _e.mock.On("MakeRoute")}
}

func (_c *Container_MakeRoute_Call) Run(run func()) *Container_MakeRoute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Container_MakeRoute_Call) Return(_a0 route.Route) *Container_MakeRoute_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Container_MakeRoute_Call) RunAndReturn(run func() route.Route) *Container_MakeRoute_Call {
	_c.Call.Return(run)
	return _c
}

// MakeSchedule provides a mock function with given fields:
func (_m *Container) MakeSchedule() schedule.Schedule {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for MakeSchedule")
	}

	var r0 schedule.Schedule
	if rf, ok := ret.Get(0).(func() schedule.Schedule); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(schedule.Schedule)
		}
	}

	return r0
}

// Container_MakeSchedule_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MakeSchedule'
type Container_MakeSchedule_Call struct {
	*mock.Call
}

// MakeSchedule is a helper method to define mock.On call
func (_e *Container_Expecter) MakeSchedule() *Container_MakeSchedule_Call {
	return &Container_MakeSchedule_Call{Call: _e.mock.On("MakeSchedule")}
}

func (_c *Container_MakeSchedule_Call) Run(run func()) *Container_MakeSchedule_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Container_MakeSchedule_Call) Return(_a0 schedule.Schedule) *Container_MakeSchedule_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Container_MakeSchedule_Call) RunAndReturn(run func() schedule.Schedule) *Container_MakeSchedule_Call {
	_c.Call.Return(run)
	return _c
}

// MakeSchema provides a mock function with given fields:
func (_m *Container) MakeSchema() schema.Schema {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for MakeSchema")
	}

	var r0 schema.Schema
	if rf, ok := ret.Get(0).(func() schema.Schema); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(schema.Schema)
		}
	}

	return r0
}

// Container_MakeSchema_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MakeSchema'
type Container_MakeSchema_Call struct {
	*mock.Call
}

// MakeSchema is a helper method to define mock.On call
func (_e *Container_Expecter) MakeSchema() *Container_MakeSchema_Call {
	return &Container_MakeSchema_Call{Call: _e.mock.On("MakeSchema")}
}

func (_c *Container_MakeSchema_Call) Run(run func()) *Container_MakeSchema_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Container_MakeSchema_Call) Return(_a0 schema.Schema) *Container_MakeSchema_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Container_MakeSchema_Call) RunAndReturn(run func() schema.Schema) *Container_MakeSchema_Call {
	_c.Call.Return(run)
	return _c
}

// MakeSeeder provides a mock function with given fields:
func (_m *Container) MakeSeeder() seeder.Facade {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for MakeSeeder")
	}

	var r0 seeder.Facade
	if rf, ok := ret.Get(0).(func() seeder.Facade); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(seeder.Facade)
		}
	}

	return r0
}

// Container_MakeSeeder_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MakeSeeder'
type Container_MakeSeeder_Call struct {
	*mock.Call
}

// MakeSeeder is a helper method to define mock.On call
func (_e *Container_Expecter) MakeSeeder() *Container_MakeSeeder_Call {
	return &Container_MakeSeeder_Call{Call: _e.mock.On("MakeSeeder")}
}

func (_c *Container_MakeSeeder_Call) Run(run func()) *Container_MakeSeeder_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Container_MakeSeeder_Call) Return(_a0 seeder.Facade) *Container_MakeSeeder_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Container_MakeSeeder_Call) RunAndReturn(run func() seeder.Facade) *Container_MakeSeeder_Call {
	_c.Call.Return(run)
	return _c
}

// MakeSession provides a mock function with given fields:
func (_m *Container) MakeSession() session.Manager {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for MakeSession")
	}

	var r0 session.Manager
	if rf, ok := ret.Get(0).(func() session.Manager); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(session.Manager)
		}
	}

	return r0
}

// Container_MakeSession_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MakeSession'
type Container_MakeSession_Call struct {
	*mock.Call
}

// MakeSession is a helper method to define mock.On call
func (_e *Container_Expecter) MakeSession() *Container_MakeSession_Call {
	return &Container_MakeSession_Call{Call: _e.mock.On("MakeSession")}
}

func (_c *Container_MakeSession_Call) Run(run func()) *Container_MakeSession_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Container_MakeSession_Call) Return(_a0 session.Manager) *Container_MakeSession_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Container_MakeSession_Call) RunAndReturn(run func() session.Manager) *Container_MakeSession_Call {
	_c.Call.Return(run)
	return _c
}

// MakeStorage provides a mock function with given fields:
func (_m *Container) MakeStorage() filesystem.Storage {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for MakeStorage")
	}

	var r0 filesystem.Storage
	if rf, ok := ret.Get(0).(func() filesystem.Storage); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(filesystem.Storage)
		}
	}

	return r0
}

// Container_MakeStorage_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MakeStorage'
type Container_MakeStorage_Call struct {
	*mock.Call
}

// MakeStorage is a helper method to define mock.On call
func (_e *Container_Expecter) MakeStorage() *Container_MakeStorage_Call {
	return &Container_MakeStorage_Call{Call: _e.mock.On("MakeStorage")}
}

func (_c *Container_MakeStorage_Call) Run(run func()) *Container_MakeStorage_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Container_MakeStorage_Call) Return(_a0 filesystem.Storage) *Container_MakeStorage_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Container_MakeStorage_Call) RunAndReturn(run func() filesystem.Storage) *Container_MakeStorage_Call {
	_c.Call.Return(run)
	return _c
}

// MakeTesting provides a mock function with given fields:
func (_m *Container) MakeTesting() testing.Testing {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for MakeTesting")
	}

	var r0 testing.Testing
	if rf, ok := ret.Get(0).(func() testing.Testing); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(testing.Testing)
		}
	}

	return r0
}

// Container_MakeTesting_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MakeTesting'
type Container_MakeTesting_Call struct {
	*mock.Call
}

// MakeTesting is a helper method to define mock.On call
func (_e *Container_Expecter) MakeTesting() *Container_MakeTesting_Call {
	return &Container_MakeTesting_Call{Call: _e.mock.On("MakeTesting")}
}

func (_c *Container_MakeTesting_Call) Run(run func()) *Container_MakeTesting_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Container_MakeTesting_Call) Return(_a0 testing.Testing) *Container_MakeTesting_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Container_MakeTesting_Call) RunAndReturn(run func() testing.Testing) *Container_MakeTesting_Call {
	_c.Call.Return(run)
	return _c
}

// MakeValidation provides a mock function with given fields:
func (_m *Container) MakeValidation() validation.Validation {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for MakeValidation")
	}

	var r0 validation.Validation
	if rf, ok := ret.Get(0).(func() validation.Validation); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(validation.Validation)
		}
	}

	return r0
}

// Container_MakeValidation_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MakeValidation'
type Container_MakeValidation_Call struct {
	*mock.Call
}

// MakeValidation is a helper method to define mock.On call
func (_e *Container_Expecter) MakeValidation() *Container_MakeValidation_Call {
	return &Container_MakeValidation_Call{Call: _e.mock.On("MakeValidation")}
}

func (_c *Container_MakeValidation_Call) Run(run func()) *Container_MakeValidation_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Container_MakeValidation_Call) Return(_a0 validation.Validation) *Container_MakeValidation_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Container_MakeValidation_Call) RunAndReturn(run func() validation.Validation) *Container_MakeValidation_Call {
	_c.Call.Return(run)
	return _c
}

// MakeView provides a mock function with given fields:
func (_m *Container) MakeView() http.View {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for MakeView")
	}

	var r0 http.View
	if rf, ok := ret.Get(0).(func() http.View); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(http.View)
		}
	}

	return r0
}

// Container_MakeView_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MakeView'
type Container_MakeView_Call struct {
	*mock.Call
}

// MakeView is a helper method to define mock.On call
func (_e *Container_Expecter) MakeView() *Container_MakeView_Call {
	return &Container_MakeView_Call{Call: _e.mock.On("MakeView")}
}

func (_c *Container_MakeView_Call) Run(run func()) *Container_MakeView_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Container_MakeView_Call) Return(_a0 http.View) *Container_MakeView_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Container_MakeView_Call) RunAndReturn(run func() http.View) *Container_MakeView_Call {
	_c.Call.Return(run)
	return _c
}

// MakeWith provides a mock function with given fields: key, parameters
func (_m *Container) MakeWith(key interface{}, parameters map[string]interface{}) (interface{}, error) {
	ret := _m.Called(key, parameters)

	if len(ret) == 0 {
		panic("no return value specified for MakeWith")
	}

	var r0 interface{}
	var r1 error
	if rf, ok := ret.Get(0).(func(interface{}, map[string]interface{}) (interface{}, error)); ok {
		return rf(key, parameters)
	}
	if rf, ok := ret.Get(0).(func(interface{}, map[string]interface{}) interface{}); ok {
		r0 = rf(key, parameters)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(interface{})
		}
	}

	if rf, ok := ret.Get(1).(func(interface{}, map[string]interface{}) error); ok {
		r1 = rf(key, parameters)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Container_MakeWith_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MakeWith'
type Container_MakeWith_Call struct {
	*mock.Call
}

// MakeWith is a helper method to define mock.On call
//   - key interface{}
//   - parameters map[string]interface{}
func (_e *Container_Expecter) MakeWith(key interface{}, parameters interface{}) *Container_MakeWith_Call {
	return &Container_MakeWith_Call{Call: _e.mock.On("MakeWith", key, parameters)}
}

func (_c *Container_MakeWith_Call) Run(run func(key interface{}, parameters map[string]interface{})) *Container_MakeWith_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(interface{}), args[1].(map[string]interface{}))
	})
	return _c
}

func (_c *Container_MakeWith_Call) Return(_a0 interface{}, _a1 error) *Container_MakeWith_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Container_MakeWith_Call) RunAndReturn(run func(interface{}, map[string]interface{}) (interface{}, error)) *Container_MakeWith_Call {
	_c.Call.Return(run)
	return _c
}

// Singleton provides a mock function with given fields: key, callback
func (_m *Container) Singleton(key interface{}, callback func(foundation.Application) (interface{}, error)) {
	_m.Called(key, callback)
}

// Container_Singleton_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Singleton'
type Container_Singleton_Call struct {
	*mock.Call
}

// Singleton is a helper method to define mock.On call
//   - key interface{}
//   - callback func(foundation.Application)(interface{} , error)
func (_e *Container_Expecter) Singleton(key interface{}, callback interface{}) *Container_Singleton_Call {
	return &Container_Singleton_Call{Call: _e.mock.On("Singleton", key, callback)}
}

func (_c *Container_Singleton_Call) Run(run func(key interface{}, callback func(foundation.Application) (interface{}, error))) *Container_Singleton_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(interface{}), args[1].(func(foundation.Application) (interface{}, error)))
	})
	return _c
}

func (_c *Container_Singleton_Call) Return() *Container_Singleton_Call {
	_c.Call.Return()
	return _c
}

func (_c *Container_Singleton_Call) RunAndReturn(run func(interface{}, func(foundation.Application) (interface{}, error))) *Container_Singleton_Call {
	_c.Call.Return(run)
	return _c
}

// NewContainer creates a new instance of Container. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewContainer(t interface {
	mock.TestingT
	Cleanup(func())
}) *Container {
	mock := &Container{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

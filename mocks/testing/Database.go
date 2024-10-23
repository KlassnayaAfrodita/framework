// Code generated by mockery. DO NOT EDIT.

package testing

import (
	database "github.com/goravel/framework/contracts/database"
	mock "github.com/stretchr/testify/mock"

	seeder "github.com/goravel/framework/contracts/database/seeder"

	testing "github.com/goravel/framework/contracts/testing"
)

// Database is an autogenerated mock type for the Database type
type Database struct {
	mock.Mock
}

type Database_Expecter struct {
	mock *mock.Mock
}

func (_m *Database) EXPECT() *Database_Expecter {
	return &Database_Expecter{mock: &_m.Mock}
}

// Build provides a mock function with given fields:
func (_m *Database) Build() error {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Build")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Database_Build_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Build'
type Database_Build_Call struct {
	*mock.Call
}

// Build is a helper method to define mock.On call
func (_e *Database_Expecter) Build() *Database_Build_Call {
	return &Database_Build_Call{Call: _e.mock.On("Build")}
}

func (_c *Database_Build_Call) Run(run func()) *Database_Build_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Database_Build_Call) Return(_a0 error) *Database_Build_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Database_Build_Call) RunAndReturn(run func() error) *Database_Build_Call {
	_c.Call.Return(run)
	return _c
}

// Config provides a mock function with given fields:
func (_m *Database) Config() testing.DatabaseConfig {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Config")
	}

	var r0 testing.DatabaseConfig
	if rf, ok := ret.Get(0).(func() testing.DatabaseConfig); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(testing.DatabaseConfig)
	}

	return r0
}

// Database_Config_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Config'
type Database_Config_Call struct {
	*mock.Call
}

// Config is a helper method to define mock.On call
func (_e *Database_Expecter) Config() *Database_Config_Call {
	return &Database_Config_Call{Call: _e.mock.On("Config")}
}

func (_c *Database_Config_Call) Run(run func()) *Database_Config_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Database_Config_Call) Return(_a0 testing.DatabaseConfig) *Database_Config_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Database_Config_Call) RunAndReturn(run func() testing.DatabaseConfig) *Database_Config_Call {
	_c.Call.Return(run)
	return _c
}

// Driver provides a mock function with given fields:
func (_m *Database) Driver() database.Driver {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Driver")
	}

	var r0 database.Driver
	if rf, ok := ret.Get(0).(func() database.Driver); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(database.Driver)
	}

	return r0
}

// Database_Driver_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Driver'
type Database_Driver_Call struct {
	*mock.Call
}

// Driver is a helper method to define mock.On call
func (_e *Database_Expecter) Driver() *Database_Driver_Call {
	return &Database_Driver_Call{Call: _e.mock.On("Driver")}
}

func (_c *Database_Driver_Call) Run(run func()) *Database_Driver_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Database_Driver_Call) Return(_a0 database.Driver) *Database_Driver_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Database_Driver_Call) RunAndReturn(run func() database.Driver) *Database_Driver_Call {
	_c.Call.Return(run)
	return _c
}

// Fresh provides a mock function with given fields:
func (_m *Database) Fresh() error {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Fresh")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Database_Fresh_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Fresh'
type Database_Fresh_Call struct {
	*mock.Call
}

// Fresh is a helper method to define mock.On call
func (_e *Database_Expecter) Fresh() *Database_Fresh_Call {
	return &Database_Fresh_Call{Call: _e.mock.On("Fresh")}
}

func (_c *Database_Fresh_Call) Run(run func()) *Database_Fresh_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Database_Fresh_Call) Return(_a0 error) *Database_Fresh_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Database_Fresh_Call) RunAndReturn(run func() error) *Database_Fresh_Call {
	_c.Call.Return(run)
	return _c
}

// Image provides a mock function with given fields: image
func (_m *Database) Image(image testing.Image) {
	_m.Called(image)
}

// Database_Image_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Image'
type Database_Image_Call struct {
	*mock.Call
}

// Image is a helper method to define mock.On call
//   - image testing.Image
func (_e *Database_Expecter) Image(image interface{}) *Database_Image_Call {
	return &Database_Image_Call{Call: _e.mock.On("Image", image)}
}

func (_c *Database_Image_Call) Run(run func(image testing.Image)) *Database_Image_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(testing.Image))
	})
	return _c
}

func (_c *Database_Image_Call) Return() *Database_Image_Call {
	_c.Call.Return()
	return _c
}

func (_c *Database_Image_Call) RunAndReturn(run func(testing.Image)) *Database_Image_Call {
	_c.Call.Return(run)
	return _c
}

// Seed provides a mock function with given fields: seeders
func (_m *Database) Seed(seeders ...seeder.Seeder) error {
	_va := make([]interface{}, len(seeders))
	for _i := range seeders {
		_va[_i] = seeders[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for Seed")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(...seeder.Seeder) error); ok {
		r0 = rf(seeders...)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Database_Seed_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Seed'
type Database_Seed_Call struct {
	*mock.Call
}

// Seed is a helper method to define mock.On call
//   - seeders ...seeder.Seeder
func (_e *Database_Expecter) Seed(seeders ...interface{}) *Database_Seed_Call {
	return &Database_Seed_Call{Call: _e.mock.On("Seed",
		append([]interface{}{}, seeders...)...)}
}

func (_c *Database_Seed_Call) Run(run func(seeders ...seeder.Seeder)) *Database_Seed_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]seeder.Seeder, len(args)-0)
		for i, a := range args[0:] {
			if a != nil {
				variadicArgs[i] = a.(seeder.Seeder)
			}
		}
		run(variadicArgs...)
	})
	return _c
}

func (_c *Database_Seed_Call) Return(_a0 error) *Database_Seed_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Database_Seed_Call) RunAndReturn(run func(...seeder.Seeder) error) *Database_Seed_Call {
	_c.Call.Return(run)
	return _c
}

// Stop provides a mock function with given fields:
func (_m *Database) Stop() error {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Stop")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Database_Stop_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Stop'
type Database_Stop_Call struct {
	*mock.Call
}

// Stop is a helper method to define mock.On call
func (_e *Database_Expecter) Stop() *Database_Stop_Call {
	return &Database_Stop_Call{Call: _e.mock.On("Stop")}
}

func (_c *Database_Stop_Call) Run(run func()) *Database_Stop_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Database_Stop_Call) Return(_a0 error) *Database_Stop_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Database_Stop_Call) RunAndReturn(run func() error) *Database_Stop_Call {
	_c.Call.Return(run)
	return _c
}

// NewDatabase creates a new instance of Database. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewDatabase(t interface {
	mock.TestingT
	Cleanup(func())
}) *Database {
	mock := &Database{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

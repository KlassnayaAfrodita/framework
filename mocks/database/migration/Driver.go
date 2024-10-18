// Code generated by mockery. DO NOT EDIT.

package migration

import mock "github.com/stretchr/testify/mock"

// Driver is an autogenerated mock type for the Driver type
type Driver struct {
	mock.Mock
}

type Driver_Expecter struct {
	mock *mock.Mock
}

func (_m *Driver) EXPECT() *Driver_Expecter {
	return &Driver_Expecter{mock: &_m.Mock}
}

// Create provides a mock function with given fields: name
func (_m *Driver) Create(name string) error {
	ret := _m.Called(name)

	if len(ret) == 0 {
		panic("no return value specified for Create")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(name)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Driver_Create_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Create'
type Driver_Create_Call struct {
	*mock.Call
}

// Create is a helper method to define mock.On call
//   - name string
func (_e *Driver_Expecter) Create(name interface{}) *Driver_Create_Call {
	return &Driver_Create_Call{Call: _e.mock.On("Create", name)}
}

func (_c *Driver_Create_Call) Run(run func(name string)) *Driver_Create_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *Driver_Create_Call) Return(_a0 error) *Driver_Create_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Driver_Create_Call) RunAndReturn(run func(string) error) *Driver_Create_Call {
	_c.Call.Return(run)
	return _c
}

// Run provides a mock function with given fields:
func (_m *Driver) Run() error {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Run")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Driver_Run_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Run'
type Driver_Run_Call struct {
	*mock.Call
}

// Run is a helper method to define mock.On call
func (_e *Driver_Expecter) Run() *Driver_Run_Call {
	return &Driver_Run_Call{Call: _e.mock.On("Run")}
}

func (_c *Driver_Run_Call) Run(run func()) *Driver_Run_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Driver_Run_Call) Return(_a0 error) *Driver_Run_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Driver_Run_Call) RunAndReturn(run func() error) *Driver_Run_Call {
	_c.Call.Return(run)
	return _c
}

// NewDriver creates a new instance of Driver. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewDriver(t interface {
	mock.TestingT
	Cleanup(func())
}) *Driver {
	mock := &Driver{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

// Code generated by mockery. DO NOT EDIT.

package orm

import mock "github.com/stretchr/testify/mock"

// Cursor is an autogenerated mock type for the Cursor type
type Cursor struct {
	mock.Mock
}

type Cursor_Expecter struct {
	mock *mock.Mock
}

func (_m *Cursor) EXPECT() *Cursor_Expecter {
	return &Cursor_Expecter{mock: &_m.Mock}
}

// Scan provides a mock function with given fields: value
func (_m *Cursor) Scan(value any) error {
	ret := _m.Called(value)

	if len(ret) == 0 {
		panic("no return value specified for Scan")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(any) error); ok {
		r0 = rf(value)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Cursor_Scan_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Scan'
type Cursor_Scan_Call struct {
	*mock.Call
}

// Scan is a helper method to define mock.On call
//   - value any
func (_e *Cursor_Expecter) Scan(value interface{}) *Cursor_Scan_Call {
	return &Cursor_Scan_Call{Call: _e.mock.On("Scan", value)}
}

func (_c *Cursor_Scan_Call) Run(run func(value any)) *Cursor_Scan_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(any))
	})
	return _c
}

func (_c *Cursor_Scan_Call) Return(_a0 error) *Cursor_Scan_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Cursor_Scan_Call) RunAndReturn(run func(any) error) *Cursor_Scan_Call {
	_c.Call.Return(run)
	return _c
}

// NewCursor creates a new instance of Cursor. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewCursor(t interface {
	mock.TestingT
	Cleanup(func())
}) *Cursor {
	mock := &Cursor{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

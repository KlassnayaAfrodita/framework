// Code generated by mockery v2.34.2. DO NOT EDIT.

package mocks

import (
	http "github.com/goravel/framework/contracts/http"
	mock "github.com/stretchr/testify/mock"
)

// ResponseView is an autogenerated mock type for the ResponseView type
type ResponseView struct {
	mock.Mock
}

type ResponseView_Expecter struct {
	mock *mock.Mock
}

func (_m *ResponseView) EXPECT() *ResponseView_Expecter {
	return &ResponseView_Expecter{mock: &_m.Mock}
}

// First provides a mock function with given fields: views, data
func (_m *ResponseView) First(views []string, data ...interface{}) http.Response {
	var _ca []interface{}
	_ca = append(_ca, views)
	_ca = append(_ca, data...)
	ret := _m.Called(_ca...)

	var r0 http.Response
	if rf, ok := ret.Get(0).(func([]string, ...interface{}) http.Response); ok {
		r0 = rf(views, data...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(http.Response)
		}
	}

	return r0
}

// ResponseView_First_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'First'
type ResponseView_First_Call struct {
	*mock.Call
}

// First is a helper method to define mock.On call
//   - views []string
//   - data ...interface{}
func (_e *ResponseView_Expecter) First(views interface{}, data ...interface{}) *ResponseView_First_Call {
	return &ResponseView_First_Call{Call: _e.mock.On("First",
		append([]interface{}{views}, data...)...)}
}

func (_c *ResponseView_First_Call) Run(run func(views []string, data ...interface{})) *ResponseView_First_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]interface{}, len(args)-1)
		for i, a := range args[1:] {
			if a != nil {
				variadicArgs[i] = a.(interface{})
			}
		}
		run(args[0].([]string), variadicArgs...)
	})
	return _c
}

func (_c *ResponseView_First_Call) Return(_a0 http.Response) *ResponseView_First_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ResponseView_First_Call) RunAndReturn(run func([]string, ...interface{}) http.Response) *ResponseView_First_Call {
	_c.Call.Return(run)
	return _c
}

// Make provides a mock function with given fields: view, data
func (_m *ResponseView) Make(view string, data ...interface{}) http.Response {
	var _ca []interface{}
	_ca = append(_ca, view)
	_ca = append(_ca, data...)
	ret := _m.Called(_ca...)

	var r0 http.Response
	if rf, ok := ret.Get(0).(func(string, ...interface{}) http.Response); ok {
		r0 = rf(view, data...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(http.Response)
		}
	}

	return r0
}

// ResponseView_Make_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Make'
type ResponseView_Make_Call struct {
	*mock.Call
}

// Make is a helper method to define mock.On call
//   - view string
//   - data ...interface{}
func (_e *ResponseView_Expecter) Make(view interface{}, data ...interface{}) *ResponseView_Make_Call {
	return &ResponseView_Make_Call{Call: _e.mock.On("Make",
		append([]interface{}{view}, data...)...)}
}

func (_c *ResponseView_Make_Call) Run(run func(view string, data ...interface{})) *ResponseView_Make_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]interface{}, len(args)-1)
		for i, a := range args[1:] {
			if a != nil {
				variadicArgs[i] = a.(interface{})
			}
		}
		run(args[0].(string), variadicArgs...)
	})
	return _c
}

func (_c *ResponseView_Make_Call) Return(_a0 http.Response) *ResponseView_Make_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ResponseView_Make_Call) RunAndReturn(run func(string, ...interface{}) http.Response) *ResponseView_Make_Call {
	_c.Call.Return(run)
	return _c
}

// NewResponseView creates a new instance of ResponseView. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewResponseView(t interface {
	mock.TestingT
	Cleanup(func())
}) *ResponseView {
	mock := &ResponseView{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

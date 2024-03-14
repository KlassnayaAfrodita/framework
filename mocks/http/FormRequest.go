// Code generated by mockery v2.34.2. DO NOT EDIT.

package mocks

import (
	http "github.com/goravel/framework/contracts/http"
	mock "github.com/stretchr/testify/mock"

	validation "github.com/goravel/framework/contracts/validation"
)

// FormRequest is an autogenerated mock type for the FormRequest type
type FormRequest struct {
	mock.Mock
}

type FormRequest_Expecter struct {
	mock *mock.Mock
}

func (_m *FormRequest) EXPECT() *FormRequest_Expecter {
	return &FormRequest_Expecter{mock: &_m.Mock}
}

// Attributes provides a mock function with given fields: ctx
func (_m *FormRequest) Attributes(ctx http.Context) map[string]string {
	ret := _m.Called(ctx)

	var r0 map[string]string
	if rf, ok := ret.Get(0).(func(http.Context) map[string]string); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[string]string)
		}
	}

	return r0
}

// FormRequest_Attributes_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Attributes'
type FormRequest_Attributes_Call struct {
	*mock.Call
}

// Attributes is a helper method to define mock.On call
//   - ctx http.Context
func (_e *FormRequest_Expecter) Attributes(ctx interface{}) *FormRequest_Attributes_Call {
	return &FormRequest_Attributes_Call{Call: _e.mock.On("Attributes", ctx)}
}

func (_c *FormRequest_Attributes_Call) Run(run func(ctx http.Context)) *FormRequest_Attributes_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(http.Context))
	})
	return _c
}

func (_c *FormRequest_Attributes_Call) Return(_a0 map[string]string) *FormRequest_Attributes_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *FormRequest_Attributes_Call) RunAndReturn(run func(http.Context) map[string]string) *FormRequest_Attributes_Call {
	_c.Call.Return(run)
	return _c
}

// Authorize provides a mock function with given fields: ctx
func (_m *FormRequest) Authorize(ctx http.Context) error {
	ret := _m.Called(ctx)

	var r0 error
	if rf, ok := ret.Get(0).(func(http.Context) error); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// FormRequest_Authorize_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Authorize'
type FormRequest_Authorize_Call struct {
	*mock.Call
}

// Authorize is a helper method to define mock.On call
//   - ctx http.Context
func (_e *FormRequest_Expecter) Authorize(ctx interface{}) *FormRequest_Authorize_Call {
	return &FormRequest_Authorize_Call{Call: _e.mock.On("Authorize", ctx)}
}

func (_c *FormRequest_Authorize_Call) Run(run func(ctx http.Context)) *FormRequest_Authorize_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(http.Context))
	})
	return _c
}

func (_c *FormRequest_Authorize_Call) Return(_a0 error) *FormRequest_Authorize_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *FormRequest_Authorize_Call) RunAndReturn(run func(http.Context) error) *FormRequest_Authorize_Call {
	_c.Call.Return(run)
	return _c
}

// Messages provides a mock function with given fields: ctx
func (_m *FormRequest) Messages(ctx http.Context) map[string]string {
	ret := _m.Called(ctx)

	var r0 map[string]string
	if rf, ok := ret.Get(0).(func(http.Context) map[string]string); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[string]string)
		}
	}

	return r0
}

// FormRequest_Messages_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Messages'
type FormRequest_Messages_Call struct {
	*mock.Call
}

// Messages is a helper method to define mock.On call
//   - ctx http.Context
func (_e *FormRequest_Expecter) Messages(ctx interface{}) *FormRequest_Messages_Call {
	return &FormRequest_Messages_Call{Call: _e.mock.On("Messages", ctx)}
}

func (_c *FormRequest_Messages_Call) Run(run func(ctx http.Context)) *FormRequest_Messages_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(http.Context))
	})
	return _c
}

func (_c *FormRequest_Messages_Call) Return(_a0 map[string]string) *FormRequest_Messages_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *FormRequest_Messages_Call) RunAndReturn(run func(http.Context) map[string]string) *FormRequest_Messages_Call {
	_c.Call.Return(run)
	return _c
}

// PrepareForValidation provides a mock function with given fields: ctx, data
func (_m *FormRequest) PrepareForValidation(ctx http.Context, data validation.Data) error {
	ret := _m.Called(ctx, data)

	var r0 error
	if rf, ok := ret.Get(0).(func(http.Context, validation.Data) error); ok {
		r0 = rf(ctx, data)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// FormRequest_PrepareForValidation_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'PrepareForValidation'
type FormRequest_PrepareForValidation_Call struct {
	*mock.Call
}

// PrepareForValidation is a helper method to define mock.On call
//   - ctx http.Context
//   - data validation.Data
func (_e *FormRequest_Expecter) PrepareForValidation(ctx interface{}, data interface{}) *FormRequest_PrepareForValidation_Call {
	return &FormRequest_PrepareForValidation_Call{Call: _e.mock.On("PrepareForValidation", ctx, data)}
}

func (_c *FormRequest_PrepareForValidation_Call) Run(run func(ctx http.Context, data validation.Data)) *FormRequest_PrepareForValidation_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(http.Context), args[1].(validation.Data))
	})
	return _c
}

func (_c *FormRequest_PrepareForValidation_Call) Return(_a0 error) *FormRequest_PrepareForValidation_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *FormRequest_PrepareForValidation_Call) RunAndReturn(run func(http.Context, validation.Data) error) *FormRequest_PrepareForValidation_Call {
	_c.Call.Return(run)
	return _c
}

// Rules provides a mock function with given fields: ctx
func (_m *FormRequest) Rules(ctx http.Context) map[string]string {
	ret := _m.Called(ctx)

	var r0 map[string]string
	if rf, ok := ret.Get(0).(func(http.Context) map[string]string); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[string]string)
		}
	}

	return r0
}

// FormRequest_Rules_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Rules'
type FormRequest_Rules_Call struct {
	*mock.Call
}

// Rules is a helper method to define mock.On call
//   - ctx http.Context
func (_e *FormRequest_Expecter) Rules(ctx interface{}) *FormRequest_Rules_Call {
	return &FormRequest_Rules_Call{Call: _e.mock.On("Rules", ctx)}
}

func (_c *FormRequest_Rules_Call) Run(run func(ctx http.Context)) *FormRequest_Rules_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(http.Context))
	})
	return _c
}

func (_c *FormRequest_Rules_Call) Return(_a0 map[string]string) *FormRequest_Rules_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *FormRequest_Rules_Call) RunAndReturn(run func(http.Context) map[string]string) *FormRequest_Rules_Call {
	_c.Call.Return(run)
	return _c
}

// NewFormRequest creates a new instance of FormRequest. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewFormRequest(t interface {
	mock.TestingT
	Cleanup(func())
}) *FormRequest {
	mock := &FormRequest{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

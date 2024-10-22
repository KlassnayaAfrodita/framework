// Code generated by mockery. DO NOT EDIT.

package validation

import (
	validation "github.com/goravel/framework/contracts/validation"
	mock "github.com/stretchr/testify/mock"
)

// Validator is an autogenerated mock type for the Validator type
type Validator struct {
	mock.Mock
}

type Validator_Expecter struct {
	mock *mock.Mock
}

func (_m *Validator) EXPECT() *Validator_Expecter {
	return &Validator_Expecter{mock: &_m.Mock}
}

// Bind provides a mock function with given fields: ptr
func (_m *Validator) Bind(ptr any) error {
	ret := _m.Called(ptr)

	if len(ret) == 0 {
		panic("no return value specified for Bind")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(any) error); ok {
		r0 = rf(ptr)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Validator_Bind_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Bind'
type Validator_Bind_Call struct {
	*mock.Call
}

// Bind is a helper method to define mock.On call
//   - ptr any
func (_e *Validator_Expecter) Bind(ptr interface{}) *Validator_Bind_Call {
	return &Validator_Bind_Call{Call: _e.mock.On("Bind", ptr)}
}

func (_c *Validator_Bind_Call) Run(run func(ptr any)) *Validator_Bind_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(any))
	})
	return _c
}

func (_c *Validator_Bind_Call) Return(_a0 error) *Validator_Bind_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Validator_Bind_Call) RunAndReturn(run func(any) error) *Validator_Bind_Call {
	_c.Call.Return(run)
	return _c
}

// Errors provides a mock function with given fields:
func (_m *Validator) Errors() validation.Errors {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Errors")
	}

	var r0 validation.Errors
	if rf, ok := ret.Get(0).(func() validation.Errors); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(validation.Errors)
		}
	}

	return r0
}

// Validator_Errors_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Errors'
type Validator_Errors_Call struct {
	*mock.Call
}

// Errors is a helper method to define mock.On call
func (_e *Validator_Expecter) Errors() *Validator_Errors_Call {
	return &Validator_Errors_Call{Call: _e.mock.On("Errors")}
}

func (_c *Validator_Errors_Call) Run(run func()) *Validator_Errors_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Validator_Errors_Call) Return(_a0 validation.Errors) *Validator_Errors_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Validator_Errors_Call) RunAndReturn(run func() validation.Errors) *Validator_Errors_Call {
	_c.Call.Return(run)
	return _c
}

// Fails provides a mock function with given fields:
func (_m *Validator) Fails() bool {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Fails")
	}

	var r0 bool
	if rf, ok := ret.Get(0).(func() bool); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// Validator_Fails_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Fails'
type Validator_Fails_Call struct {
	*mock.Call
}

// Fails is a helper method to define mock.On call
func (_e *Validator_Expecter) Fails() *Validator_Fails_Call {
	return &Validator_Fails_Call{Call: _e.mock.On("Fails")}
}

func (_c *Validator_Fails_Call) Run(run func()) *Validator_Fails_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Validator_Fails_Call) Return(_a0 bool) *Validator_Fails_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Validator_Fails_Call) RunAndReturn(run func() bool) *Validator_Fails_Call {
	_c.Call.Return(run)
	return _c
}

// NewValidator creates a new instance of Validator. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewValidator(t interface {
	mock.TestingT
	Cleanup(func())
}) *Validator {
	mock := &Validator{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

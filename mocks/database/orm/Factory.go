// Code generated by mockery. DO NOT EDIT.

package orm

import (
	orm "github.com/goravel/framework/contracts/database/orm"
	mock "github.com/stretchr/testify/mock"
)

// Factory is an autogenerated mock type for the Factory type
type Factory struct {
	mock.Mock
}

type Factory_Expecter struct {
	mock *mock.Mock
}

func (_m *Factory) EXPECT() *Factory_Expecter {
	return &Factory_Expecter{mock: &_m.Mock}
}

// Count provides a mock function with given fields: count
func (_m *Factory) Count(count int) orm.Factory {
	ret := _m.Called(count)

	if len(ret) == 0 {
		panic("no return value specified for Count")
	}

	var r0 orm.Factory
	if rf, ok := ret.Get(0).(func(int) orm.Factory); ok {
		r0 = rf(count)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(orm.Factory)
		}
	}

	return r0
}

// Factory_Count_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Count'
type Factory_Count_Call struct {
	*mock.Call
}

// Count is a helper method to define mock.On call
//   - count int
func (_e *Factory_Expecter) Count(count interface{}) *Factory_Count_Call {
	return &Factory_Count_Call{Call: _e.mock.On("Count", count)}
}

func (_c *Factory_Count_Call) Run(run func(count int)) *Factory_Count_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(int))
	})
	return _c
}

func (_c *Factory_Count_Call) Return(_a0 orm.Factory) *Factory_Count_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Factory_Count_Call) RunAndReturn(run func(int) orm.Factory) *Factory_Count_Call {
	_c.Call.Return(run)
	return _c
}

// Create provides a mock function with given fields: value, attributes
func (_m *Factory) Create(value any, attributes ...map[string]any) error {
	_va := make([]interface{}, len(attributes))
	for _i := range attributes {
		_va[_i] = attributes[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, value)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for Create")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(any, ...map[string]any) error); ok {
		r0 = rf(value, attributes...)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Factory_Create_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Create'
type Factory_Create_Call struct {
	*mock.Call
}

// Create is a helper method to define mock.On call
//   - value any
//   - attributes ...map[string]any
func (_e *Factory_Expecter) Create(value interface{}, attributes ...interface{}) *Factory_Create_Call {
	return &Factory_Create_Call{Call: _e.mock.On("Create",
		append([]interface{}{value}, attributes...)...)}
}

func (_c *Factory_Create_Call) Run(run func(value any, attributes ...map[string]any)) *Factory_Create_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]map[string]any, len(args)-1)
		for i, a := range args[1:] {
			if a != nil {
				variadicArgs[i] = a.(map[string]any)
			}
		}
		run(args[0].(any), variadicArgs...)
	})
	return _c
}

func (_c *Factory_Create_Call) Return(_a0 error) *Factory_Create_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Factory_Create_Call) RunAndReturn(run func(any, ...map[string]any) error) *Factory_Create_Call {
	_c.Call.Return(run)
	return _c
}

// CreateQuietly provides a mock function with given fields: value, attributes
func (_m *Factory) CreateQuietly(value any, attributes ...map[string]any) error {
	_va := make([]interface{}, len(attributes))
	for _i := range attributes {
		_va[_i] = attributes[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, value)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for CreateQuietly")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(any, ...map[string]any) error); ok {
		r0 = rf(value, attributes...)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Factory_CreateQuietly_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateQuietly'
type Factory_CreateQuietly_Call struct {
	*mock.Call
}

// CreateQuietly is a helper method to define mock.On call
//   - value any
//   - attributes ...map[string]any
func (_e *Factory_Expecter) CreateQuietly(value interface{}, attributes ...interface{}) *Factory_CreateQuietly_Call {
	return &Factory_CreateQuietly_Call{Call: _e.mock.On("CreateQuietly",
		append([]interface{}{value}, attributes...)...)}
}

func (_c *Factory_CreateQuietly_Call) Run(run func(value any, attributes ...map[string]any)) *Factory_CreateQuietly_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]map[string]any, len(args)-1)
		for i, a := range args[1:] {
			if a != nil {
				variadicArgs[i] = a.(map[string]any)
			}
		}
		run(args[0].(any), variadicArgs...)
	})
	return _c
}

func (_c *Factory_CreateQuietly_Call) Return(_a0 error) *Factory_CreateQuietly_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Factory_CreateQuietly_Call) RunAndReturn(run func(any, ...map[string]any) error) *Factory_CreateQuietly_Call {
	_c.Call.Return(run)
	return _c
}

// Make provides a mock function with given fields: value, attributes
func (_m *Factory) Make(value any, attributes ...map[string]any) error {
	_va := make([]interface{}, len(attributes))
	for _i := range attributes {
		_va[_i] = attributes[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, value)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for Make")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(any, ...map[string]any) error); ok {
		r0 = rf(value, attributes...)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Factory_Make_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Make'
type Factory_Make_Call struct {
	*mock.Call
}

// Make is a helper method to define mock.On call
//   - value any
//   - attributes ...map[string]any
func (_e *Factory_Expecter) Make(value interface{}, attributes ...interface{}) *Factory_Make_Call {
	return &Factory_Make_Call{Call: _e.mock.On("Make",
		append([]interface{}{value}, attributes...)...)}
}

func (_c *Factory_Make_Call) Run(run func(value any, attributes ...map[string]any)) *Factory_Make_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]map[string]any, len(args)-1)
		for i, a := range args[1:] {
			if a != nil {
				variadicArgs[i] = a.(map[string]any)
			}
		}
		run(args[0].(any), variadicArgs...)
	})
	return _c
}

func (_c *Factory_Make_Call) Return(_a0 error) *Factory_Make_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Factory_Make_Call) RunAndReturn(run func(any, ...map[string]any) error) *Factory_Make_Call {
	_c.Call.Return(run)
	return _c
}

// NewFactory creates a new instance of Factory. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewFactory(t interface {
	mock.TestingT
	Cleanup(func())
}) *Factory {
	mock := &Factory{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

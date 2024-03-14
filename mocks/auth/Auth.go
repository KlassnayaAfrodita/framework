// Code generated by mockery v2.34.2. DO NOT EDIT.

package mocks

import (
	auth "github.com/goravel/framework/contracts/auth"
	mock "github.com/stretchr/testify/mock"
)

// Auth is an autogenerated mock type for the Auth type
type Auth struct {
	mock.Mock
}

type Auth_Expecter struct {
	mock *mock.Mock
}

func (_m *Auth) EXPECT() *Auth_Expecter {
	return &Auth_Expecter{mock: &_m.Mock}
}

// Guard provides a mock function with given fields: name
func (_m *Auth) Guard(name string) auth.Auth {
	ret := _m.Called(name)

	var r0 auth.Auth
	if rf, ok := ret.Get(0).(func(string) auth.Auth); ok {
		r0 = rf(name)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(auth.Auth)
		}
	}

	return r0
}

// Auth_Guard_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Guard'
type Auth_Guard_Call struct {
	*mock.Call
}

// Guard is a helper method to define mock.On call
//   - name string
func (_e *Auth_Expecter) Guard(name interface{}) *Auth_Guard_Call {
	return &Auth_Guard_Call{Call: _e.mock.On("Guard", name)}
}

func (_c *Auth_Guard_Call) Run(run func(name string)) *Auth_Guard_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *Auth_Guard_Call) Return(_a0 auth.Auth) *Auth_Guard_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Auth_Guard_Call) RunAndReturn(run func(string) auth.Auth) *Auth_Guard_Call {
	_c.Call.Return(run)
	return _c
}

// Login provides a mock function with given fields: user
func (_m *Auth) Login(user interface{}) (string, error) {
	ret := _m.Called(user)

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(interface{}) (string, error)); ok {
		return rf(user)
	}
	if rf, ok := ret.Get(0).(func(interface{}) string); ok {
		r0 = rf(user)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(interface{}) error); ok {
		r1 = rf(user)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Auth_Login_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Login'
type Auth_Login_Call struct {
	*mock.Call
}

// Login is a helper method to define mock.On call
//   - user interface{}
func (_e *Auth_Expecter) Login(user interface{}) *Auth_Login_Call {
	return &Auth_Login_Call{Call: _e.mock.On("Login", user)}
}

func (_c *Auth_Login_Call) Run(run func(user interface{})) *Auth_Login_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(interface{}))
	})
	return _c
}

func (_c *Auth_Login_Call) Return(token string, err error) *Auth_Login_Call {
	_c.Call.Return(token, err)
	return _c
}

func (_c *Auth_Login_Call) RunAndReturn(run func(interface{}) (string, error)) *Auth_Login_Call {
	_c.Call.Return(run)
	return _c
}

// LoginUsingID provides a mock function with given fields: id
func (_m *Auth) LoginUsingID(id interface{}) (string, error) {
	ret := _m.Called(id)

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(interface{}) (string, error)); ok {
		return rf(id)
	}
	if rf, ok := ret.Get(0).(func(interface{}) string); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(interface{}) error); ok {
		r1 = rf(id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Auth_LoginUsingID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'LoginUsingID'
type Auth_LoginUsingID_Call struct {
	*mock.Call
}

// LoginUsingID is a helper method to define mock.On call
//   - id interface{}
func (_e *Auth_Expecter) LoginUsingID(id interface{}) *Auth_LoginUsingID_Call {
	return &Auth_LoginUsingID_Call{Call: _e.mock.On("LoginUsingID", id)}
}

func (_c *Auth_LoginUsingID_Call) Run(run func(id interface{})) *Auth_LoginUsingID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(interface{}))
	})
	return _c
}

func (_c *Auth_LoginUsingID_Call) Return(token string, err error) *Auth_LoginUsingID_Call {
	_c.Call.Return(token, err)
	return _c
}

func (_c *Auth_LoginUsingID_Call) RunAndReturn(run func(interface{}) (string, error)) *Auth_LoginUsingID_Call {
	_c.Call.Return(run)
	return _c
}

// Logout provides a mock function with given fields:
func (_m *Auth) Logout() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Auth_Logout_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Logout'
type Auth_Logout_Call struct {
	*mock.Call
}

// Logout is a helper method to define mock.On call
func (_e *Auth_Expecter) Logout() *Auth_Logout_Call {
	return &Auth_Logout_Call{Call: _e.mock.On("Logout")}
}

func (_c *Auth_Logout_Call) Run(run func()) *Auth_Logout_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Auth_Logout_Call) Return(_a0 error) *Auth_Logout_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Auth_Logout_Call) RunAndReturn(run func() error) *Auth_Logout_Call {
	_c.Call.Return(run)
	return _c
}

// Parse provides a mock function with given fields: token
func (_m *Auth) Parse(token string) (*auth.Payload, error) {
	ret := _m.Called(token)

	var r0 *auth.Payload
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (*auth.Payload, error)); ok {
		return rf(token)
	}
	if rf, ok := ret.Get(0).(func(string) *auth.Payload); ok {
		r0 = rf(token)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*auth.Payload)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(token)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Auth_Parse_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Parse'
type Auth_Parse_Call struct {
	*mock.Call
}

// Parse is a helper method to define mock.On call
//   - token string
func (_e *Auth_Expecter) Parse(token interface{}) *Auth_Parse_Call {
	return &Auth_Parse_Call{Call: _e.mock.On("Parse", token)}
}

func (_c *Auth_Parse_Call) Run(run func(token string)) *Auth_Parse_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *Auth_Parse_Call) Return(_a0 *auth.Payload, _a1 error) *Auth_Parse_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Auth_Parse_Call) RunAndReturn(run func(string) (*auth.Payload, error)) *Auth_Parse_Call {
	_c.Call.Return(run)
	return _c
}

// Refresh provides a mock function with given fields:
func (_m *Auth) Refresh() (string, error) {
	ret := _m.Called()

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func() (string, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Auth_Refresh_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Refresh'
type Auth_Refresh_Call struct {
	*mock.Call
}

// Refresh is a helper method to define mock.On call
func (_e *Auth_Expecter) Refresh() *Auth_Refresh_Call {
	return &Auth_Refresh_Call{Call: _e.mock.On("Refresh")}
}

func (_c *Auth_Refresh_Call) Run(run func()) *Auth_Refresh_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Auth_Refresh_Call) Return(token string, err error) *Auth_Refresh_Call {
	_c.Call.Return(token, err)
	return _c
}

func (_c *Auth_Refresh_Call) RunAndReturn(run func() (string, error)) *Auth_Refresh_Call {
	_c.Call.Return(run)
	return _c
}

// User provides a mock function with given fields: user
func (_m *Auth) User(user interface{}) error {
	ret := _m.Called(user)

	var r0 error
	if rf, ok := ret.Get(0).(func(interface{}) error); ok {
		r0 = rf(user)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Auth_User_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'User'
type Auth_User_Call struct {
	*mock.Call
}

// User is a helper method to define mock.On call
//   - user interface{}
func (_e *Auth_Expecter) User(user interface{}) *Auth_User_Call {
	return &Auth_User_Call{Call: _e.mock.On("User", user)}
}

func (_c *Auth_User_Call) Run(run func(user interface{})) *Auth_User_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(interface{}))
	})
	return _c
}

func (_c *Auth_User_Call) Return(_a0 error) *Auth_User_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Auth_User_Call) RunAndReturn(run func(interface{}) error) *Auth_User_Call {
	_c.Call.Return(run)
	return _c
}

// NewAuth creates a new instance of Auth. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewAuth(t interface {
	mock.TestingT
	Cleanup(func())
}) *Auth {
	mock := &Auth{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

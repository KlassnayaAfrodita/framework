// Code generated by mockery. DO NOT EDIT.

package filesystem

import (
	filesystem "github.com/goravel/framework/contracts/filesystem"
	mock "github.com/stretchr/testify/mock"

	time "time"
)

// File is an autogenerated mock type for the File type
type File struct {
	mock.Mock
}

type File_Expecter struct {
	mock *mock.Mock
}

func (_m *File) EXPECT() *File_Expecter {
	return &File_Expecter{mock: &_m.Mock}
}

// Disk provides a mock function with given fields: disk
func (_m *File) Disk(disk string) filesystem.File {
	ret := _m.Called(disk)

	if len(ret) == 0 {
		panic("no return value specified for Disk")
	}

	var r0 filesystem.File
	if rf, ok := ret.Get(0).(func(string) filesystem.File); ok {
		r0 = rf(disk)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(filesystem.File)
		}
	}

	return r0
}

// File_Disk_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Disk'
type File_Disk_Call struct {
	*mock.Call
}

// Disk is a helper method to define mock.On call
//   - disk string
func (_e *File_Expecter) Disk(disk interface{}) *File_Disk_Call {
	return &File_Disk_Call{Call: _e.mock.On("Disk", disk)}
}

func (_c *File_Disk_Call) Run(run func(disk string)) *File_Disk_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *File_Disk_Call) Return(_a0 filesystem.File) *File_Disk_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *File_Disk_Call) RunAndReturn(run func(string) filesystem.File) *File_Disk_Call {
	_c.Call.Return(run)
	return _c
}

// Extension provides a mock function with given fields:
func (_m *File) Extension() (string, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Extension")
	}

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

// File_Extension_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Extension'
type File_Extension_Call struct {
	*mock.Call
}

// Extension is a helper method to define mock.On call
func (_e *File_Expecter) Extension() *File_Extension_Call {
	return &File_Extension_Call{Call: _e.mock.On("Extension")}
}

func (_c *File_Extension_Call) Run(run func()) *File_Extension_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *File_Extension_Call) Return(_a0 string, _a1 error) *File_Extension_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *File_Extension_Call) RunAndReturn(run func() (string, error)) *File_Extension_Call {
	_c.Call.Return(run)
	return _c
}

// File provides a mock function with given fields:
func (_m *File) File() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for File")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// File_File_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'File'
type File_File_Call struct {
	*mock.Call
}

// File is a helper method to define mock.On call
func (_e *File_Expecter) File() *File_File_Call {
	return &File_File_Call{Call: _e.mock.On("File")}
}

func (_c *File_File_Call) Run(run func()) *File_File_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *File_File_Call) Return(_a0 string) *File_File_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *File_File_Call) RunAndReturn(run func() string) *File_File_Call {
	_c.Call.Return(run)
	return _c
}

// GetClientOriginalExtension provides a mock function with given fields:
func (_m *File) GetClientOriginalExtension() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetClientOriginalExtension")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// File_GetClientOriginalExtension_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetClientOriginalExtension'
type File_GetClientOriginalExtension_Call struct {
	*mock.Call
}

// GetClientOriginalExtension is a helper method to define mock.On call
func (_e *File_Expecter) GetClientOriginalExtension() *File_GetClientOriginalExtension_Call {
	return &File_GetClientOriginalExtension_Call{Call: _e.mock.On("GetClientOriginalExtension")}
}

func (_c *File_GetClientOriginalExtension_Call) Run(run func()) *File_GetClientOriginalExtension_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *File_GetClientOriginalExtension_Call) Return(_a0 string) *File_GetClientOriginalExtension_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *File_GetClientOriginalExtension_Call) RunAndReturn(run func() string) *File_GetClientOriginalExtension_Call {
	_c.Call.Return(run)
	return _c
}

// GetClientOriginalName provides a mock function with given fields:
func (_m *File) GetClientOriginalName() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetClientOriginalName")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// File_GetClientOriginalName_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetClientOriginalName'
type File_GetClientOriginalName_Call struct {
	*mock.Call
}

// GetClientOriginalName is a helper method to define mock.On call
func (_e *File_Expecter) GetClientOriginalName() *File_GetClientOriginalName_Call {
	return &File_GetClientOriginalName_Call{Call: _e.mock.On("GetClientOriginalName")}
}

func (_c *File_GetClientOriginalName_Call) Run(run func()) *File_GetClientOriginalName_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *File_GetClientOriginalName_Call) Return(_a0 string) *File_GetClientOriginalName_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *File_GetClientOriginalName_Call) RunAndReturn(run func() string) *File_GetClientOriginalName_Call {
	_c.Call.Return(run)
	return _c
}

// HashName provides a mock function with given fields: path
func (_m *File) HashName(path ...string) string {
	_va := make([]interface{}, len(path))
	for _i := range path {
		_va[_i] = path[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for HashName")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func(...string) string); ok {
		r0 = rf(path...)
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// File_HashName_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'HashName'
type File_HashName_Call struct {
	*mock.Call
}

// HashName is a helper method to define mock.On call
//   - path ...string
func (_e *File_Expecter) HashName(path ...interface{}) *File_HashName_Call {
	return &File_HashName_Call{Call: _e.mock.On("HashName",
		append([]interface{}{}, path...)...)}
}

func (_c *File_HashName_Call) Run(run func(path ...string)) *File_HashName_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]string, len(args)-0)
		for i, a := range args[0:] {
			if a != nil {
				variadicArgs[i] = a.(string)
			}
		}
		run(variadicArgs...)
	})
	return _c
}

func (_c *File_HashName_Call) Return(_a0 string) *File_HashName_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *File_HashName_Call) RunAndReturn(run func(...string) string) *File_HashName_Call {
	_c.Call.Return(run)
	return _c
}

// LastModified provides a mock function with given fields:
func (_m *File) LastModified() (time.Time, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for LastModified")
	}

	var r0 time.Time
	var r1 error
	if rf, ok := ret.Get(0).(func() (time.Time, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() time.Time); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(time.Time)
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// File_LastModified_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'LastModified'
type File_LastModified_Call struct {
	*mock.Call
}

// LastModified is a helper method to define mock.On call
func (_e *File_Expecter) LastModified() *File_LastModified_Call {
	return &File_LastModified_Call{Call: _e.mock.On("LastModified")}
}

func (_c *File_LastModified_Call) Run(run func()) *File_LastModified_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *File_LastModified_Call) Return(_a0 time.Time, _a1 error) *File_LastModified_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *File_LastModified_Call) RunAndReturn(run func() (time.Time, error)) *File_LastModified_Call {
	_c.Call.Return(run)
	return _c
}

// MimeType provides a mock function with given fields:
func (_m *File) MimeType() (string, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for MimeType")
	}

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

// File_MimeType_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'MimeType'
type File_MimeType_Call struct {
	*mock.Call
}

// MimeType is a helper method to define mock.On call
func (_e *File_Expecter) MimeType() *File_MimeType_Call {
	return &File_MimeType_Call{Call: _e.mock.On("MimeType")}
}

func (_c *File_MimeType_Call) Run(run func()) *File_MimeType_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *File_MimeType_Call) Return(_a0 string, _a1 error) *File_MimeType_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *File_MimeType_Call) RunAndReturn(run func() (string, error)) *File_MimeType_Call {
	_c.Call.Return(run)
	return _c
}

// Size provides a mock function with given fields:
func (_m *File) Size() (int64, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Size")
	}

	var r0 int64
	var r1 error
	if rf, ok := ret.Get(0).(func() (int64, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() int64); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(int64)
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// File_Size_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Size'
type File_Size_Call struct {
	*mock.Call
}

// Size is a helper method to define mock.On call
func (_e *File_Expecter) Size() *File_Size_Call {
	return &File_Size_Call{Call: _e.mock.On("Size")}
}

func (_c *File_Size_Call) Run(run func()) *File_Size_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *File_Size_Call) Return(_a0 int64, _a1 error) *File_Size_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *File_Size_Call) RunAndReturn(run func() (int64, error)) *File_Size_Call {
	_c.Call.Return(run)
	return _c
}

// Store provides a mock function with given fields: path
func (_m *File) Store(path string) (string, error) {
	ret := _m.Called(path)

	if len(ret) == 0 {
		panic("no return value specified for Store")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (string, error)); ok {
		return rf(path)
	}
	if rf, ok := ret.Get(0).(func(string) string); ok {
		r0 = rf(path)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(path)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// File_Store_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Store'
type File_Store_Call struct {
	*mock.Call
}

// Store is a helper method to define mock.On call
//   - path string
func (_e *File_Expecter) Store(path interface{}) *File_Store_Call {
	return &File_Store_Call{Call: _e.mock.On("Store", path)}
}

func (_c *File_Store_Call) Run(run func(path string)) *File_Store_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *File_Store_Call) Return(_a0 string, _a1 error) *File_Store_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *File_Store_Call) RunAndReturn(run func(string) (string, error)) *File_Store_Call {
	_c.Call.Return(run)
	return _c
}

// StoreAs provides a mock function with given fields: path, name
func (_m *File) StoreAs(path string, name string) (string, error) {
	ret := _m.Called(path, name)

	if len(ret) == 0 {
		panic("no return value specified for StoreAs")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(string, string) (string, error)); ok {
		return rf(path, name)
	}
	if rf, ok := ret.Get(0).(func(string, string) string); ok {
		r0 = rf(path, name)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(string, string) error); ok {
		r1 = rf(path, name)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// File_StoreAs_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'StoreAs'
type File_StoreAs_Call struct {
	*mock.Call
}

// StoreAs is a helper method to define mock.On call
//   - path string
//   - name string
func (_e *File_Expecter) StoreAs(path interface{}, name interface{}) *File_StoreAs_Call {
	return &File_StoreAs_Call{Call: _e.mock.On("StoreAs", path, name)}
}

func (_c *File_StoreAs_Call) Run(run func(path string, name string)) *File_StoreAs_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(string))
	})
	return _c
}

func (_c *File_StoreAs_Call) Return(_a0 string, _a1 error) *File_StoreAs_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *File_StoreAs_Call) RunAndReturn(run func(string, string) (string, error)) *File_StoreAs_Call {
	_c.Call.Return(run)
	return _c
}

// NewFile creates a new instance of File. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewFile(t interface {
	mock.TestingT
	Cleanup(func())
}) *File {
	mock := &File{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

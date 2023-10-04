// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/clients/inventorygroups/client.go

// Package mock_inventorygroups is a generated GoMock package.
package mock_inventorygroups

import (
	url "net/url"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	inventorygroups "github.com/redhatinsights/edge-api/pkg/clients/inventorygroups"
)

// MockClientInterface is a mock of ClientInterface interface.
type MockClientInterface struct {
	ctrl     *gomock.Controller
	recorder *MockClientInterfaceMockRecorder
}

// MockClientInterfaceMockRecorder is the mock recorder for MockClientInterface.
type MockClientInterfaceMockRecorder struct {
	mock *MockClientInterface
}

// NewMockClientInterface creates a new mock instance.
func NewMockClientInterface(ctrl *gomock.Controller) *MockClientInterface {
	mock := &MockClientInterface{ctrl: ctrl}
	mock.recorder = &MockClientInterfaceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockClientInterface) EXPECT() *MockClientInterfaceMockRecorder {
	return m.recorder
}

// AddHostsToGroup mocks base method.
func (m *MockClientInterface) AddHostsToGroup(groupUUID string, hosts []string) (*inventorygroups.Group, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddHostsToGroup", groupUUID, hosts)
	ret0, _ := ret[0].(*inventorygroups.Group)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AddHostsToGroup indicates an expected call of AddHostsToGroup.
func (mr *MockClientInterfaceMockRecorder) AddHostsToGroup(groupUUID, hosts interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddHostsToGroup", reflect.TypeOf((*MockClientInterface)(nil).AddHostsToGroup), groupUUID, hosts)
}

// CreateGroup mocks base method.
func (m *MockClientInterface) CreateGroup(groupName string, hostIDS []string) (*inventorygroups.Group, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateGroup", groupName, hostIDS)
	ret0, _ := ret[0].(*inventorygroups.Group)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateGroup indicates an expected call of CreateGroup.
func (mr *MockClientInterfaceMockRecorder) CreateGroup(groupName, hostIDS interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateGroup", reflect.TypeOf((*MockClientInterface)(nil).CreateGroup), groupName, hostIDS)
}

// GetBaseURL mocks base method.
func (m *MockClientInterface) GetBaseURL() (*url.URL, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBaseURL")
	ret0, _ := ret[0].(*url.URL)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetBaseURL indicates an expected call of GetBaseURL.
func (mr *MockClientInterfaceMockRecorder) GetBaseURL() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBaseURL", reflect.TypeOf((*MockClientInterface)(nil).GetBaseURL))
}

// GetGroupByName mocks base method.
func (m *MockClientInterface) GetGroupByName(name string) (*inventorygroups.Group, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGroupByName", name)
	ret0, _ := ret[0].(*inventorygroups.Group)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetGroupByName indicates an expected call of GetGroupByName.
func (mr *MockClientInterfaceMockRecorder) GetGroupByName(name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGroupByName", reflect.TypeOf((*MockClientInterface)(nil).GetGroupByName), name)
}

// GetGroupByUUID mocks base method.
func (m *MockClientInterface) GetGroupByUUID(groupUUID string) (*inventorygroups.Group, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGroupByUUID", groupUUID)
	ret0, _ := ret[0].(*inventorygroups.Group)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetGroupByUUID indicates an expected call of GetGroupByUUID.
func (mr *MockClientInterfaceMockRecorder) GetGroupByUUID(groupUUID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGroupByUUID", reflect.TypeOf((*MockClientInterface)(nil).GetGroupByUUID), groupUUID)
}

// ListGroups mocks base method.
func (m *MockClientInterface) ListGroups(requestParams inventorygroups.ListGroupsParams) (*inventorygroups.Response, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListGroups", requestParams)
	ret0, _ := ret[0].(*inventorygroups.Response)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListGroups indicates an expected call of ListGroups.
func (mr *MockClientInterfaceMockRecorder) ListGroups(requestParams interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListGroups", reflect.TypeOf((*MockClientInterface)(nil).ListGroups), requestParams)
}

// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/services/repobuilder.go

// Package mock_services is a generated GoMock package.
package mock_services

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	models "github.com/redhatinsights/edge-api/pkg/models"
)

// MockRepoBuilderInterface is a mock of RepoBuilderInterface interface.
type MockRepoBuilderInterface struct {
	ctrl     *gomock.Controller
	recorder *MockRepoBuilderInterfaceMockRecorder
}

// MockRepoBuilderInterfaceMockRecorder is the mock recorder for MockRepoBuilderInterface.
type MockRepoBuilderInterfaceMockRecorder struct {
	mock *MockRepoBuilderInterface
}

// NewMockRepoBuilderInterface creates a new mock instance.
func NewMockRepoBuilderInterface(ctrl *gomock.Controller) *MockRepoBuilderInterface {
	mock := &MockRepoBuilderInterface{ctrl: ctrl}
	mock.recorder = &MockRepoBuilderInterfaceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRepoBuilderInterface) EXPECT() *MockRepoBuilderInterfaceMockRecorder {
	return m.recorder
}

// BuildUpdateRepo mocks base method.
func (m *MockRepoBuilderInterface) BuildUpdateRepo(id uint) (*models.UpdateTransaction, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BuildUpdateRepo", id)
	ret0, _ := ret[0].(*models.UpdateTransaction)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// BuildUpdateRepo indicates an expected call of BuildUpdateRepo.
func (mr *MockRepoBuilderInterfaceMockRecorder) BuildUpdateRepo(id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BuildUpdateRepo", reflect.TypeOf((*MockRepoBuilderInterface)(nil).BuildUpdateRepo), id)
}

// DownloadVersionRepo mocks base method.
func (m *MockRepoBuilderInterface) DownloadVersionRepo(c *models.Commit, dest string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DownloadVersionRepo", c, dest)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DownloadVersionRepo indicates an expected call of DownloadVersionRepo.
func (mr *MockRepoBuilderInterfaceMockRecorder) DownloadVersionRepo(c, dest interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DownloadVersionRepo", reflect.TypeOf((*MockRepoBuilderInterface)(nil).DownloadVersionRepo), c, dest)
}

// ExtractVersionRepo mocks base method.
func (m *MockRepoBuilderInterface) ExtractVersionRepo(c *models.Commit, tarFileName, dest string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ExtractVersionRepo", c, tarFileName, dest)
	ret0, _ := ret[0].(error)
	return ret0
}

// ExtractVersionRepo indicates an expected call of ExtractVersionRepo.
func (mr *MockRepoBuilderInterfaceMockRecorder) ExtractVersionRepo(c, tarFileName, dest interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExtractVersionRepo", reflect.TypeOf((*MockRepoBuilderInterface)(nil).ExtractVersionRepo), c, tarFileName, dest)
}

// ImportRepo mocks base method.
func (m *MockRepoBuilderInterface) ImportRepo(r *models.Repo) (*models.Repo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ImportRepo", r)
	ret0, _ := ret[0].(*models.Repo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ImportRepo indicates an expected call of ImportRepo.
func (mr *MockRepoBuilderInterfaceMockRecorder) ImportRepo(r interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ImportRepo", reflect.TypeOf((*MockRepoBuilderInterface)(nil).ImportRepo), r)
}

// RepoPullLocalStaticDeltas mocks base method.
func (m *MockRepoBuilderInterface) RepoPullLocalStaticDeltas(u, o *models.Commit, uprepo, oldrepo string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RepoPullLocalStaticDeltas", u, o, uprepo, oldrepo)
	ret0, _ := ret[0].(error)
	return ret0
}

// RepoPullLocalStaticDeltas indicates an expected call of RepoPullLocalStaticDeltas.
func (mr *MockRepoBuilderInterfaceMockRecorder) RepoPullLocalStaticDeltas(u, o, uprepo, oldrepo interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RepoPullLocalStaticDeltas", reflect.TypeOf((*MockRepoBuilderInterface)(nil).RepoPullLocalStaticDeltas), u, o, uprepo, oldrepo)
}

// UploadVersionRepo mocks base method.
func (m *MockRepoBuilderInterface) UploadVersionRepo(c *models.Commit, tarFileName string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UploadVersionRepo", c, tarFileName)
	ret0, _ := ret[0].(error)
	return ret0
}

// UploadVersionRepo indicates an expected call of UploadVersionRepo.
func (mr *MockRepoBuilderInterfaceMockRecorder) UploadVersionRepo(c, tarFileName interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UploadVersionRepo", reflect.TypeOf((*MockRepoBuilderInterface)(nil).UploadVersionRepo), c, tarFileName)
}

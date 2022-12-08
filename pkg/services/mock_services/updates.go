// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/services/updates.go

// Package mock_services is a generated GoMock package.
package mock_services

import (
	context "context"
	io "io"
	os "os"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	models "github.com/redhatinsights/edge-api/pkg/models"
	services "github.com/redhatinsights/edge-api/pkg/services"
)

// MockUpdateServiceInterface is a mock of UpdateServiceInterface interface.
type MockUpdateServiceInterface struct {
	ctrl     *gomock.Controller
	recorder *MockUpdateServiceInterfaceMockRecorder
}

// MockUpdateServiceInterfaceMockRecorder is the mock recorder for MockUpdateServiceInterface.
type MockUpdateServiceInterfaceMockRecorder struct {
	mock *MockUpdateServiceInterface
}

// NewMockUpdateServiceInterface creates a new mock instance.
func NewMockUpdateServiceInterface(ctrl *gomock.Controller) *MockUpdateServiceInterface {
	mock := &MockUpdateServiceInterface{ctrl: ctrl}
	mock.recorder = &MockUpdateServiceInterfaceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockUpdateServiceInterface) EXPECT() *MockUpdateServiceInterfaceMockRecorder {
	return m.recorder
}

// BuildUpdateRepo mocks base method.
func (m *MockUpdateServiceInterface) BuildUpdateRepo(orgID string, updateID uint) (*models.UpdateTransaction, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BuildUpdateRepo", orgID, updateID)
	ret0, _ := ret[0].(*models.UpdateTransaction)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// BuildUpdateRepo indicates an expected call of BuildUpdateRepo.
func (mr *MockUpdateServiceInterfaceMockRecorder) BuildUpdateRepo(orgID, updateID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BuildUpdateRepo", reflect.TypeOf((*MockUpdateServiceInterface)(nil).BuildUpdateRepo), orgID, updateID)
}

// BuildUpdateTransactions mocks base method.
func (m *MockUpdateServiceInterface) BuildUpdateTransactions(devicesUpdate *models.DevicesUpdate, orgID string, commit *models.Commit) (*[]models.UpdateTransaction, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BuildUpdateTransactions", devicesUpdate, orgID, commit)
	ret0, _ := ret[0].(*[]models.UpdateTransaction)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// BuildUpdateTransactions indicates an expected call of BuildUpdateTransactions.
func (mr *MockUpdateServiceInterfaceMockRecorder) BuildUpdateTransactions(devicesUpdate, orgID, commit interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BuildUpdateTransactions", reflect.TypeOf((*MockUpdateServiceInterface)(nil).BuildUpdateTransactions), devicesUpdate, orgID, commit)
}

// CreateUpdate mocks base method.
func (m *MockUpdateServiceInterface) CreateUpdate(id uint) (*models.UpdateTransaction, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateUpdate", id)
	ret0, _ := ret[0].(*models.UpdateTransaction)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateUpdate indicates an expected call of CreateUpdate.
func (mr *MockUpdateServiceInterfaceMockRecorder) CreateUpdate(id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateUpdate", reflect.TypeOf((*MockUpdateServiceInterface)(nil).CreateUpdate), id)
}

// CreateUpdateAsync mocks base method.
func (m *MockUpdateServiceInterface) CreateUpdateAsync(id uint) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "CreateUpdateAsync", id)
}

// CreateUpdateAsync indicates an expected call of CreateUpdateAsync.
func (mr *MockUpdateServiceInterfaceMockRecorder) CreateUpdateAsync(id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateUpdateAsync", reflect.TypeOf((*MockUpdateServiceInterface)(nil).CreateUpdateAsync), id)
}

// GetUpdatePlaybook mocks base method.
func (m *MockUpdateServiceInterface) GetUpdatePlaybook(update *models.UpdateTransaction) (io.ReadCloser, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUpdatePlaybook", update)
	ret0, _ := ret[0].(io.ReadCloser)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUpdatePlaybook indicates an expected call of GetUpdatePlaybook.
func (mr *MockUpdateServiceInterfaceMockRecorder) GetUpdatePlaybook(update interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUpdatePlaybook", reflect.TypeOf((*MockUpdateServiceInterface)(nil).GetUpdatePlaybook), update)
}

// GetUpdateTransactionsForDevice mocks base method.
func (m *MockUpdateServiceInterface) GetUpdateTransactionsForDevice(device *models.Device) (*[]models.UpdateTransaction, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUpdateTransactionsForDevice", device)
	ret0, _ := ret[0].(*[]models.UpdateTransaction)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUpdateTransactionsForDevice indicates an expected call of GetUpdateTransactionsForDevice.
func (mr *MockUpdateServiceInterfaceMockRecorder) GetUpdateTransactionsForDevice(device interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUpdateTransactionsForDevice", reflect.TypeOf((*MockUpdateServiceInterface)(nil).GetUpdateTransactionsForDevice), device)
}

// ProcessPlaybookDispatcherRunEvent mocks base method.
func (m *MockUpdateServiceInterface) ProcessPlaybookDispatcherRunEvent(message []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ProcessPlaybookDispatcherRunEvent", message)
	ret0, _ := ret[0].(error)
	return ret0
}

// ProcessPlaybookDispatcherRunEvent indicates an expected call of ProcessPlaybookDispatcherRunEvent.
func (mr *MockUpdateServiceInterfaceMockRecorder) ProcessPlaybookDispatcherRunEvent(message interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ProcessPlaybookDispatcherRunEvent", reflect.TypeOf((*MockUpdateServiceInterface)(nil).ProcessPlaybookDispatcherRunEvent), message)
}

// ProduceEvent mocks base method.
func (m *MockUpdateServiceInterface) ProduceEvent(requestedTopic, recordKey string, event models.CRCCloudEvent) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ProduceEvent", requestedTopic, recordKey, event)
	ret0, _ := ret[0].(error)
	return ret0
}

// ProduceEvent indicates an expected call of ProduceEvent.
func (mr *MockUpdateServiceInterfaceMockRecorder) ProduceEvent(requestedTopic, recordKey, event interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ProduceEvent", reflect.TypeOf((*MockUpdateServiceInterface)(nil).ProduceEvent), requestedTopic, recordKey, event)
}

// SendDeviceNotification mocks base method.
func (m *MockUpdateServiceInterface) SendDeviceNotification(update *models.UpdateTransaction) (services.ImageNotification, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendDeviceNotification", update)
	ret0, _ := ret[0].(services.ImageNotification)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SendDeviceNotification indicates an expected call of SendDeviceNotification.
func (mr *MockUpdateServiceInterfaceMockRecorder) SendDeviceNotification(update interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendDeviceNotification", reflect.TypeOf((*MockUpdateServiceInterface)(nil).SendDeviceNotification), update)
}

// SetUpdateErrorStatusWhenInterrupted mocks base method.
func (m *MockUpdateServiceInterface) SetUpdateErrorStatusWhenInterrupted(update models.UpdateTransaction, sigint chan os.Signal, intCtx context.Context, intCancel context.CancelFunc) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetUpdateErrorStatusWhenInterrupted", update, sigint, intCtx, intCancel)
}

// SetUpdateErrorStatusWhenInterrupted indicates an expected call of SetUpdateErrorStatusWhenInterrupted.
func (mr *MockUpdateServiceInterfaceMockRecorder) SetUpdateErrorStatusWhenInterrupted(update, sigint, intCtx, intCancel interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetUpdateErrorStatusWhenInterrupted", reflect.TypeOf((*MockUpdateServiceInterface)(nil).SetUpdateErrorStatusWhenInterrupted), update, sigint, intCtx, intCancel)
}

// SetUpdateStatus mocks base method.
func (m *MockUpdateServiceInterface) SetUpdateStatus(update *models.UpdateTransaction) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetUpdateStatus", update)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetUpdateStatus indicates an expected call of SetUpdateStatus.
func (mr *MockUpdateServiceInterfaceMockRecorder) SetUpdateStatus(update interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetUpdateStatus", reflect.TypeOf((*MockUpdateServiceInterface)(nil).SetUpdateStatus), update)
}

// SetUpdateStatusBasedOnDispatchRecord mocks base method.
func (m *MockUpdateServiceInterface) SetUpdateStatusBasedOnDispatchRecord(dispatchRecord models.DispatchRecord) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetUpdateStatusBasedOnDispatchRecord", dispatchRecord)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetUpdateStatusBasedOnDispatchRecord indicates an expected call of SetUpdateStatusBasedOnDispatchRecord.
func (mr *MockUpdateServiceInterfaceMockRecorder) SetUpdateStatusBasedOnDispatchRecord(dispatchRecord interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetUpdateStatusBasedOnDispatchRecord", reflect.TypeOf((*MockUpdateServiceInterface)(nil).SetUpdateStatusBasedOnDispatchRecord), dispatchRecord)
}

// UpdateDevicesFromUpdateTransaction mocks base method.
func (m *MockUpdateServiceInterface) UpdateDevicesFromUpdateTransaction(update models.UpdateTransaction) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateDevicesFromUpdateTransaction", update)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateDevicesFromUpdateTransaction indicates an expected call of UpdateDevicesFromUpdateTransaction.
func (mr *MockUpdateServiceInterfaceMockRecorder) UpdateDevicesFromUpdateTransaction(update interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateDevicesFromUpdateTransaction", reflect.TypeOf((*MockUpdateServiceInterface)(nil).UpdateDevicesFromUpdateTransaction), update)
}

// ValidateUpdateDeviceGroup mocks base method.
func (m *MockUpdateServiceInterface) ValidateUpdateDeviceGroup(orgID string, deviceGroupID uint) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ValidateUpdateDeviceGroup", orgID, deviceGroupID)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ValidateUpdateDeviceGroup indicates an expected call of ValidateUpdateDeviceGroup.
func (mr *MockUpdateServiceInterfaceMockRecorder) ValidateUpdateDeviceGroup(orgID, deviceGroupID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ValidateUpdateDeviceGroup", reflect.TypeOf((*MockUpdateServiceInterface)(nil).ValidateUpdateDeviceGroup), orgID, deviceGroupID)
}

// ValidateUpdateSelection mocks base method.
func (m *MockUpdateServiceInterface) ValidateUpdateSelection(orgID string, imageIds []uint) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ValidateUpdateSelection", orgID, imageIds)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ValidateUpdateSelection indicates an expected call of ValidateUpdateSelection.
func (mr *MockUpdateServiceInterfaceMockRecorder) ValidateUpdateSelection(orgID, imageIds interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ValidateUpdateSelection", reflect.TypeOf((*MockUpdateServiceInterface)(nil).ValidateUpdateSelection), orgID, imageIds)
}

// WriteTemplate mocks base method.
func (m *MockUpdateServiceInterface) WriteTemplate(templateInfo services.TemplateRemoteInfo, orgID string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WriteTemplate", templateInfo, orgID)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// WriteTemplate indicates an expected call of WriteTemplate.
func (mr *MockUpdateServiceInterfaceMockRecorder) WriteTemplate(templateInfo, orgID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WriteTemplate", reflect.TypeOf((*MockUpdateServiceInterface)(nil).WriteTemplate), templateInfo, orgID)
}

package routes

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi"
	"github.com/redhatinsights/edge-api/pkg/clients/inventory"
	"github.com/redhatinsights/edge-api/pkg/dependencies"
	"github.com/redhatinsights/edge-api/pkg/errors"
	"github.com/redhatinsights/edge-api/pkg/services"
)

// MakeDevicesRouter adds support for operations on invetory
func MakeInventoryRouter(sub chi.Router) {
	sub.Get("/", GetInventory)
}

type InventoryData struct {
	Total    int
	Count    int
	Page     int
	Per_page int
	Results  []InventoryResponse
}

type InventoryResponse struct {
	ID         string
	DeviceName string
	LastSeen   string
	ImageInfo  *services.ImageInfo
}

func InventoyCtx(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if per_page := chi.URLParam(r, "per_page"); per_page != "" {
			_, err := strconv.Atoi(per_page)
			if err != nil {
				err := errors.NewBadRequest(err.Error())
				w.WriteHeader(err.GetStatus())
				json.NewEncoder(w).Encode(&err)
				return
			}
		}
		if page := chi.URLParam(r, "page"); page != "" {
			_, err := strconv.Atoi(page)
			if err != nil {
				err := errors.NewBadRequest(err.Error())
				w.WriteHeader(err.GetStatus())
				json.NewEncoder(w).Encode(&err)
				return
			}
		}
		order_by := chi.URLParam(r, "order_by")
		order_how := chi.URLParam(r, "order_how")

		// 	ctx := context.WithValue(r.Context(), imageSetKey, &imageSet)
		// 	next.ServeHTTP(w, r.WithContext(ctx))

	})
}
func GetInventory(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("entrei na rota/n")
	ctx := r.Context()
	client := inventory.InitClient(ctx)
	var InventoryData InventoryData
	var results []InventoryResponse
	//IF PARAMS FROM CONTEXT COMES WITH VALUE, SET AS PARAM
	//client.FilterParams
	inventory, err := client.ReturnDevices()
	if err != nil || inventory.Count == 0 {
		err := errors.NewNotFound(fmt.Sprintf("No devices found "))
		w.WriteHeader(err.GetStatus())

	}

	results = getUpdateAvailableInfo(r, inventory)

	InventoryData.Count = inventory.Count
	InventoryData.Total = inventory.Total
	InventoryData.Results = results

	json.NewEncoder(w).Encode(InventoryData)
}

func getUpdateAvailableInfo(r *http.Request, inventory inventory.Response) (IvtResponse []InventoryResponse) {
	var ivt []InventoryResponse
	services, _ := r.Context().Value(dependencies.Key).(*dependencies.EdgeAPIServices)
	deviceService := services.DeviceService

	for _, device := range inventory.Result {
		var i InventoryResponse
		imageInfo, err := deviceService.GetDeviceImageInfo(device.ID)
		i.ID = device.ID
		i.DeviceName = device.DisplayName
		i.LastSeen = device.LastSeen

		if err != nil {
			i.ImageInfo = nil

		} else if imageInfo != nil {
			i.ImageInfo = imageInfo
		}
		ivt = append(ivt, i)
	}
	return ivt
}

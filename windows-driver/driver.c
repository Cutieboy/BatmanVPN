#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmtypes.h>
#include <mstcpip.h>
#include <initguid.h>

#include "public.h"

static UINT32 connect_callout_id;
static UINT32 bind_callout_id;
static UINT32 connect_v6_callout_id;
static UINT32 bind_v6_callout_id;
static PDEVICE_OBJECT control_device;

static const MOUSEVPN_REDIRECT_CONTEXT* get_redirect_context(
    const FWPS_FILTER0* filter)
{
    const FWPM_PROVIDER_CONTEXT0* context;
    const MOUSEVPN_REDIRECT_CONTEXT* redirect;

    if (filter == NULL || filter->providerContext == NULL) {
        return NULL;
    }
    context = filter->providerContext;
    if (context->type != FWPM_GENERAL_CONTEXT ||
        context->dataBuffer == NULL ||
        context->dataBuffer->data == NULL ||
        context->dataBuffer->size < sizeof(MOUSEVPN_REDIRECT_CONTEXT)) {
        return NULL;
    }
    redirect = (const MOUSEVPN_REDIRECT_CONTEXT*)context->dataBuffer->data;
    return redirect;
}

static BOOLEAN is_local_destination_v6(const FWP_BYTE_ARRAY16* bytes)
{
    IN6_ADDR address;
    if (bytes == NULL) {
        return TRUE;
    }
    RtlCopyMemory(&address, bytes->byteArray16, sizeof(address));
    return IN6_IS_ADDR_UNSPECIFIED(&address) ||
        IN6_IS_ADDR_LOOPBACK(&address) ||
        IN6_IS_ADDR_LINKLOCAL(&address) ||
        IN6_IS_ADDR_SITELOCAL(&address) ||
        IN6_IS_ADDR_MULTICAST(&address) ||
        (address.u.Byte[0] & 0xfe) == 0xfc;
}

static BOOLEAN is_local_destination(UINT32 network_order_address)
{
    IN_ADDR address;
    address.S_un.S_addr = RtlUlongByteSwap(network_order_address);
    return IN4_IS_ADDR_LOOPBACK(&address) ||
        IN4_IS_ADDR_LINKLOCAL(&address) ||
        IN4_IS_ADDR_RFC1918(&address) ||
        IN4_IS_ADDR_MC_LINKLOCAL(&address) ||
        IN4_IS_ADDR_BROADCAST(&address) ||
        IN4_IS_ADDR_MC_ADMINLOCAL(&address);
}

static void NTAPI classify_connect_v4(
    const FWPS_INCOMING_VALUES0* values,
    const FWPS_INCOMING_METADATA_VALUES0* metadata,
    void* layer_data,
    const void* classify_context,
    const FWPS_FILTER0* filter,
    UINT64 flow_context,
    FWPS_CLASSIFY_OUT0* output)
{
    UINT64 handle = 0;
    FWPS_CONNECT_REQUEST0* request = NULL;
    const MOUSEVPN_REDIRECT_CONTEXT* redirect;
    NTSTATUS status;
    SOCKADDR_IN* local;
    UINT32 flags;

    UNREFERENCED_PARAMETER(metadata);
    UNREFERENCED_PARAMETER(layer_data);
    UNREFERENCED_PARAMETER(flow_context);

    output->actionType = FWP_ACTION_PERMIT;
    if (values == NULL || filter == NULL ||
        (output->rights & FWPS_RIGHT_ACTION_WRITE) == 0 ||
        values->layerId != FWPS_LAYER_ALE_CONNECT_REDIRECT_V4) {
        return;
    }
    flags = values->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_FLAGS].value.uint32;
    if ((flags & FWP_CONDITION_FLAG_IS_REAUTHORIZE) != 0 ||
        is_local_destination(values->incomingValue[
            FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS].value.uint32) ||
        ((redirect = get_redirect_context(filter)) == NULL) ||
        redirect->family != AF_INET) {
        return;
    }

    status = FwpsAcquireClassifyHandle0((void*)classify_context, 0, &handle);
    if (!NT_SUCCESS(status)) {
        return;
    }
    status = FwpsAcquireWritableLayerDataPointer0(
        handle, filter->filterId, 0, (void**)&request, output);
    if (NT_SUCCESS(status) && request != NULL) {
        local = (SOCKADDR_IN*)&request->localAddressAndPort;
        local->sin_family = AF_INET;
        local->sin_addr = redirect->address.ipv4;
        FwpsApplyModifiedLayerData0(handle, request, 0);
        request = NULL;
    }
    if (request != NULL) {
        FwpsApplyModifiedLayerData0(handle, request, 0);
    }
    FwpsReleaseClassifyHandle0(handle);
}

static void NTAPI classify_connect_v6(
    const FWPS_INCOMING_VALUES0* values,
    const FWPS_INCOMING_METADATA_VALUES0* metadata,
    void* layer_data,
    const void* classify_context,
    const FWPS_FILTER0* filter,
    UINT64 flow_context,
    FWPS_CLASSIFY_OUT0* output)
{
    UINT64 handle = 0;
    FWPS_CONNECT_REQUEST0* request = NULL;
    const MOUSEVPN_REDIRECT_CONTEXT* redirect;
    NTSTATUS status;
    SOCKADDR_IN6* local;
    UINT32 flags;

    UNREFERENCED_PARAMETER(metadata);
    UNREFERENCED_PARAMETER(layer_data);
    UNREFERENCED_PARAMETER(flow_context);
    output->actionType = FWP_ACTION_PERMIT;
    if (values == NULL || filter == NULL ||
        (output->rights & FWPS_RIGHT_ACTION_WRITE) == 0 ||
        values->layerId != FWPS_LAYER_ALE_CONNECT_REDIRECT_V6) {
        return;
    }
    flags = values->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_FLAGS].value.uint32;
    redirect = get_redirect_context(filter);
    if ((flags & FWP_CONDITION_FLAG_IS_REAUTHORIZE) != 0 ||
        is_local_destination_v6(values->incomingValue[
            FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_ADDRESS].value.byteArray16) ||
        redirect == NULL || redirect->family != AF_INET6) {
        return;
    }
    status = FwpsAcquireClassifyHandle0((void*)classify_context, 0, &handle);
    if (!NT_SUCCESS(status)) {
        return;
    }
    status = FwpsAcquireWritableLayerDataPointer0(
        handle, filter->filterId, 0, (void**)&request, output);
    if (NT_SUCCESS(status) && request != NULL) {
        local = (SOCKADDR_IN6*)&request->localAddressAndPort;
        local->sin6_family = AF_INET6;
        local->sin6_addr = redirect->address.ipv6;
        FwpsApplyModifiedLayerData0(handle, request, 0);
        request = NULL;
    }
    if (request != NULL) {
        FwpsApplyModifiedLayerData0(handle, request, 0);
    }
    FwpsReleaseClassifyHandle0(handle);
}

static void NTAPI classify_bind_v4(
    const FWPS_INCOMING_VALUES0* values,
    const FWPS_INCOMING_METADATA_VALUES0* metadata,
    void* layer_data,
    const void* classify_context,
    const FWPS_FILTER0* filter,
    UINT64 flow_context,
    FWPS_CLASSIFY_OUT0* output)
{
    UINT64 handle = 0;
    FWPS_BIND_REQUEST0* request = NULL;
    const MOUSEVPN_REDIRECT_CONTEXT* redirect;
    NTSTATUS status;
    SOCKADDR_IN* local;
    UINT32 flags;

    UNREFERENCED_PARAMETER(metadata);
    UNREFERENCED_PARAMETER(layer_data);
    UNREFERENCED_PARAMETER(flow_context);

    output->actionType = FWP_ACTION_PERMIT;
    if (values == NULL || filter == NULL ||
        (output->rights & FWPS_RIGHT_ACTION_WRITE) == 0 ||
        values->layerId != FWPS_LAYER_ALE_BIND_REDIRECT_V4) {
        return;
    }
    flags = values->incomingValue[FWPS_FIELD_ALE_BIND_REDIRECT_V4_FLAGS].value.uint32;
    redirect = get_redirect_context(filter);
    if ((flags & FWP_CONDITION_FLAG_IS_REAUTHORIZE) != 0 ||
        redirect == NULL || redirect->family != AF_INET) {
        return;
    }

    status = FwpsAcquireClassifyHandle0((void*)classify_context, 0, &handle);
    if (!NT_SUCCESS(status)) {
        return;
    }
    status = FwpsAcquireWritableLayerDataPointer0(
        handle, filter->filterId, 0, (void**)&request, output);
    if (NT_SUCCESS(status) && request != NULL) {
        local = (SOCKADDR_IN*)&request->localAddressAndPort;
        local->sin_family = AF_INET;
        local->sin_addr = redirect->address.ipv4;
        FwpsApplyModifiedLayerData0(handle, request, 0);
        request = NULL;
    }
    if (request != NULL) {
        FwpsApplyModifiedLayerData0(handle, request, 0);
    }
    FwpsReleaseClassifyHandle0(handle);
}

static void NTAPI classify_bind_v6(
    const FWPS_INCOMING_VALUES0* values,
    const FWPS_INCOMING_METADATA_VALUES0* metadata,
    void* layer_data,
    const void* classify_context,
    const FWPS_FILTER0* filter,
    UINT64 flow_context,
    FWPS_CLASSIFY_OUT0* output)
{
    UINT64 handle = 0;
    FWPS_BIND_REQUEST0* request = NULL;
    const MOUSEVPN_REDIRECT_CONTEXT* redirect;
    NTSTATUS status;
    SOCKADDR_IN6* local;
    UINT32 flags;

    UNREFERENCED_PARAMETER(metadata);
    UNREFERENCED_PARAMETER(layer_data);
    UNREFERENCED_PARAMETER(flow_context);
    output->actionType = FWP_ACTION_PERMIT;
    if (values == NULL || filter == NULL ||
        (output->rights & FWPS_RIGHT_ACTION_WRITE) == 0 ||
        values->layerId != FWPS_LAYER_ALE_BIND_REDIRECT_V6) {
        return;
    }
    flags = values->incomingValue[FWPS_FIELD_ALE_BIND_REDIRECT_V6_FLAGS].value.uint32;
    redirect = get_redirect_context(filter);
    if ((flags & FWP_CONDITION_FLAG_IS_REAUTHORIZE) != 0 ||
        redirect == NULL || redirect->family != AF_INET6) {
        return;
    }
    status = FwpsAcquireClassifyHandle0((void*)classify_context, 0, &handle);
    if (!NT_SUCCESS(status)) {
        return;
    }
    status = FwpsAcquireWritableLayerDataPointer0(
        handle, filter->filterId, 0, (void**)&request, output);
    if (NT_SUCCESS(status) && request != NULL) {
        local = (SOCKADDR_IN6*)&request->localAddressAndPort;
        local->sin6_family = AF_INET6;
        local->sin6_addr = redirect->address.ipv6;
        FwpsApplyModifiedLayerData0(handle, request, 0);
        request = NULL;
    }
    if (request != NULL) {
        FwpsApplyModifiedLayerData0(handle, request, 0);
    }
    FwpsReleaseClassifyHandle0(handle);
}

static NTSTATUS register_callout(
    const GUID* key,
    FWPS_CALLOUT_CLASSIFY_FN0 classify,
    UINT32* callout_id)
{
    FWPS_CALLOUT0 callout;
    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey = *key;
    callout.classifyFn = classify;
    return FwpsCalloutRegister0(control_device, &callout, callout_id);
}

static void unregister_callouts(void)
{
    if (bind_v6_callout_id != 0) {
        FwpsCalloutUnregisterById0(bind_v6_callout_id);
        bind_v6_callout_id = 0;
    }
    if (connect_v6_callout_id != 0) {
        FwpsCalloutUnregisterById0(connect_v6_callout_id);
        connect_v6_callout_id = 0;
    }
    if (bind_callout_id != 0) {
        FwpsCalloutUnregisterById0(bind_callout_id);
        bind_callout_id = 0;
    }
    if (connect_callout_id != 0) {
        FwpsCalloutUnregisterById0(connect_callout_id);
        connect_callout_id = 0;
    }
}

static void unload_driver(PDRIVER_OBJECT driver_object)
{
    UNREFERENCED_PARAMETER(driver_object);

    unregister_callouts();
    if (control_device != NULL) {
        IoDeleteDevice(control_device);
        control_device = NULL;
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(registry_path);
    status = IoCreateDevice(
        driver_object, 0, NULL, FILE_DEVICE_NETWORK, 0, FALSE, &control_device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = register_callout(
        &MOUSEVPN_CALLOUT_CONNECT_V4, classify_connect_v4, &connect_callout_id);
    if (NT_SUCCESS(status)) {
        status = register_callout(
            &MOUSEVPN_CALLOUT_BIND_V4, classify_bind_v4, &bind_callout_id);
    }
    if (NT_SUCCESS(status)) {
        status = register_callout(
            &MOUSEVPN_CALLOUT_CONNECT_V6, classify_connect_v6, &connect_v6_callout_id);
    }
    if (NT_SUCCESS(status)) {
        status = register_callout(
            &MOUSEVPN_CALLOUT_BIND_V6, classify_bind_v6, &bind_v6_callout_id);
    }
    if (!NT_SUCCESS(status)) {
        unload_driver(driver_object);
        return status;
    }

    driver_object->DriverUnload = unload_driver;
    control_device->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}

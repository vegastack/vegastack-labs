package metadata

func operatorAccessSchemas() []SchemaDefinition {
	id := func(s string) string { return "vegastack-labs.dev/operator-" + s }
	list := func(name, field, item string) SchemaDefinition {
		return phase5Schema(id(name), FieldDefinition{JSONName: field, GoName: map[string]string{"people": "People", "devices": "Devices", "grants": "Grants"}[field], Kind: ValueArray, Required: true, ItemRef: id(item), MaxItems: intPointer(100)}, FieldDefinition{JSONName: "nextAfter", GoName: "NextAfter", Kind: ValueString, Required: true, MaxLength: intPointer(128)}, phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch"))
	}
	return []SchemaDefinition{
		phase5Schema(id("provider"), phase5ID("capability", "Capability"), FieldDefinition{JSONName: "configured", GoName: "Configured", Kind: ValueBoolean, Required: true}, phase5Enum("connectivity", "Connectivity", "unknown", "unavailable")),
		phase5Schema(id("provider-list"), FieldDefinition{JSONName: "providers", GoName: "Providers", Kind: ValueArray, Required: true, ItemRef: id("provider"), MaxItems: intPointer(16)}, phase5Nonnegative("stateRevision", "StateRevision"), phase5Nonnegative("recoveryEpoch", "RecoveryEpoch")),
		phase5Schema(id("person"), phase5ID("principalId", "PrincipalID"), phase5Enum("status", "Status", "active", "suspended", "revoked"), phase5Positive("grantRevision", "GrantRevision")),
		phase5Schema(id("device"), phase5ID("deviceId", "DeviceID"), phase5ID("principalId", "PrincipalID"), phase5Enum("status", "Status", "pending", "approved", "revoked"), phase5Positive("deviceRevision", "DeviceRevision")),
		phase5Schema(id("grant"), phase5ID("grantId", "GrantID"), phase5ID("principalId", "PrincipalID"), phase5ID("role", "Role"), phase5ID("action", "Action"), phase5ID("capability", "Capability"), phase5ID("resourceKind", "ResourceKind"), phase5ID("resourceId", "ResourceID"), FieldDefinition{JSONName: "branch", GoName: "Branch", Kind: ValueString, Required: true, Enum: []string{"", "human", "preauthorized"}}, phase5Enum("status", "Status", "active", "revoked"), phase5Positive("grantRevision", "GrantRevision")),
		list("people-page", "people", "person"), list("device-list", "devices", "device"), list("grant-list", "grants", "grant"),
		{ID: id("read-query"), Version: "1.0.0", Fields: []FieldDefinition{{JSONName: "principalId", GoName: "PrincipalID", Kind: ValueString, MaxLength: intPointer(128)}, {JSONName: "after", GoName: "After", Kind: ValueString, MaxLength: intPointer(128)}, {JSONName: "limit", GoName: "Limit", Kind: ValueInteger, Minimum: int64Pointer(1), Maximum: int64Pointer(100)}}},
	}
}
func operatorAccessEndpoints() []EndpointDefinition {
	var endpoints []EndpointDefinition
	for _, v := range []struct{ name, schema string }{{"people", "people-page"}, {"devices", "device-list"}, {"grants", "grant-list"}} {
		e := phase5Endpoint("api.v1."+v.name+".list", "GET", "/api/v1/"+v.name, "", "vegastack-labs.dev/operator-"+v.schema, true)
		e.OwnerPhase = "7"
		e.Availability = AvailabilityAvailable
		e.QuerySchema = "vegastack-labs.dev/operator-read-query"
		endpoints = append(endpoints, e)
	}
	e := phase5Endpoint("api.v1.providers.list", "GET", "/api/v1/providers", "", "vegastack-labs.dev/operator-provider-list", true)
	e.OwnerPhase = "7"
	e.Availability = AvailabilityAvailable
	endpoints = append(endpoints, e)
	return endpoints
}

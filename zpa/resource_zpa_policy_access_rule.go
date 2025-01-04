package zpa

import (
	"fmt"
	"log"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/zscaler/zscaler-sdk-go/v2/zpa/services/policysetcontroller"
)

func resourcePolicyAccessRule() *schema.Resource {
	return &schema.Resource{
		Create: resourcePolicyAccessCreate,
		Read:   resourcePolicyAccessRead,
		Update: resourcePolicyAccessUpdate,
		Delete: resourcePolicyAccessDelete,
		Importer: &schema.ResourceImporter{
			StateContext: importPolicyStateContextFunc([]string{"ACCESS_POLICY", "GLOBAL_POLICY"}),
		},

		Schema: MergeSchema(
			CommonPolicySchema(), map[string]*schema.Schema{
				"action": {
					Type:        schema.TypeString,
					Optional:    true,
					Description: "This is for providing the rule action.",
					ValidateFunc: validation.StringInSlice([]string{
						"ALLOW",
						"DENY",
						"REQUIRE_APPROVAL",
					}, false),
				},
				"app_server_groups": {
					Type:        schema.TypeList,
					Optional:    true,
					Computed:    true,
					Description: "List of the server group IDs.",
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"id": {
								Type:     schema.TypeList,
								Required: true,
								Elem: &schema.Schema{
									Type: schema.TypeString,
								},
							},
						},
					},
				},
				"app_connector_groups": {
					Type:        schema.TypeList,
					Optional:    true,
					Computed:    true,
					Description: "List of app-connector IDs.",
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"id": {
								Type:     schema.TypeList,
								Required: true,
								Elem: &schema.Schema{
									Type: schema.TypeString,
								},
							},
						},
					},
				},
				"conditions": GetPolicyConditionsSchema([]string{
					"APP",
					"APP_GROUP",
					"LOCATION",
					"IDP",
					"SAML",
					"SCIM",
					"SCIM_GROUP",
					"CLIENT_TYPE",
					"POSTURE",
					"TRUSTED_NETWORK",
					"BRANCH_CONNECTOR_GROUP",
					"EDGE_CONNECTOR_GROUP",
					"MACHINE_GRP",
					"COUNTRY_CODE",
					"PLATFORM",
					"RISK_FACTOR_TYPE",
					"CHROME_ENTERPRISE",
				}),
			},
		),
	}
}

func resourcePolicyAccessCreate(d *schema.ResourceData, meta interface{}) error {
	zClient := meta.(*Client)
	service := zClient.PolicySetController

	log.Printf("[DEBUG] Raw app_connector_groups data: %+v", d.Get("app_connector_groups"))
	log.Printf("[DEBUG] Raw app_server_groups data: %+v", d.Get("app_server_groups"))

	var policySetID string
	var err error

	if v, ok := d.GetOk("policy_set_id"); ok {
		policySetID = v.(string)
	} else {
		policySetID, err = fetchPolicySetIDByType(zClient, "ACCESS_POLICY")
		if err != nil {
			return err
		}
	}

	req, err := expandCreatePolicyRule(d, policySetID)
	if err != nil {
		return err
	}

	log.Printf("[DEBUG] Creating ZPA policy access rule with request:\n%+v\n", req)

	resp, _, err := policysetcontroller.CreateRule(service, req)
	if err != nil {
		return err
	}

	log.Printf("[DEBUG] Created policy rule response: %+v", resp)
	d.SetId(resp.ID)

	return resourcePolicyAccessRead(d, meta)
}

func resourcePolicyAccessRead(d *schema.ResourceData, meta interface{}) error {
	zClient := meta.(*Client)
	microTenantID := GetString(d.Get("microtenant_id"))

	policySetID, err := fetchPolicySetIDByType(zClient, "ACCESS_POLICY", microTenantID)
	if err != nil {
		return err
	}

	service := zClient.PolicySetController
	if microTenantID != "" {
		service = service.WithMicroTenant(microTenantID)
	}

	log.Printf("[INFO] Getting Policy Set Rule: policySetID:%s id: %s\n", policySetID, d.Id())
	resp, respErr, err := policysetcontroller.GetPolicyRule(service, policySetID, d.Id())
	if err != nil {
		if respErr != nil && (respErr.StatusCode == 404 || respErr.StatusCode == http.StatusNotFound) {
			log.Printf("[WARN] Removing policy rule %s from state because it no longer exists in ZPA", d.Id())
			d.SetId("")
			return nil
		}
		return err
	}

	log.Printf("[INFO] Got Policy Set Rule:\n%+v\n", resp)
	d.SetId(resp.ID)
	_ = d.Set("description", resp.Description)
	_ = d.Set("name", resp.Name)
	_ = d.Set("action", resp.Action)
	_ = d.Set("action_id", resp.ActionID)
	_ = d.Set("custom_msg", resp.CustomMsg)
	_ = d.Set("default_rule", resp.DefaultRule)
	_ = d.Set("operator", resp.Operator)
	_ = d.Set("policy_set_id", policySetID)
	_ = d.Set("policy_type", resp.PolicyType)
	_ = d.Set("priority", resp.Priority)
	_ = d.Set("lss_default_rule", resp.LSSDefaultRule)
	_ = d.Set("microtenant_id", microTenantID)
	_ = d.Set("conditions", flattenPolicyConditions(resp.Conditions))
	_ = d.Set("app_server_groups", flattenCommonAppServerGroups(resp.AppServerGroups))
	if len(resp.AppConnectorGroups) > 0 {
		if err := d.Set("app_connector_groups", flattenCommonAppConnectorGroups(resp.AppConnectorGroups)); err != nil {
			return fmt.Errorf("error setting app_connector_groups: %s", err)
		}
	}

	return nil
}

func resourcePolicyAccessUpdate(d *schema.ResourceData, meta interface{}) error {
	zClient := meta.(*Client)
	service := zClient.PolicySetController

	microTenantID := GetString(d.Get("microtenant_id"))
	if microTenantID != "" {
		service = service.WithMicroTenant(microTenantID)
	}

	var policySetID string
	var err error

	if v, ok := d.GetOk("policy_set_id"); ok {
		policySetID = v.(string)
	} else {
		policySetID, err = fetchPolicySetIDByType(zClient, "ACCESS_POLICY", microTenantID)
		if err != nil {
			return err
		}
	}

	ruleID := d.Id()
	req, err := expandCreatePolicyRule(d, policySetID)
	if err != nil {
		return err
	}

	if err := ValidateConditions(req.Conditions, zClient, microTenantID); err != nil {
		return err
	}

	if _, err := policysetcontroller.UpdateRule(service, policySetID, ruleID, req); err != nil {
		return err
	}

	return resourcePolicyAccessRead(d, meta)
}

func resourcePolicyAccessDelete(d *schema.ResourceData, meta interface{}) error {
	zClient := meta.(*Client)
	service := zClient.PolicySetController

	microTenantID := GetString(d.Get("microtenant_id"))
	if microTenantID != "" {
		service = service.WithMicroTenant(microTenantID)
	}

	var policySetID string
	var err error

	if v, ok := d.GetOk("policy_set_id"); ok {
		policySetID = v.(string)
	} else {
		policySetID, err = fetchPolicySetIDByType(zClient, "ACCESS_POLICY", microTenantID)
		if err != nil {
			return err
		}
	}

	log.Printf("[INFO] Deleting policy set rule with id %v\n", d.Id())

	if _, err := policysetcontroller.Delete(service, policySetID, d.Id()); err != nil {
		return err
	}

	return nil
}

func expandCreatePolicyRule(d *schema.ResourceData, policySetID string) (*policysetcontroller.PolicyRule, error) {
	conditions, err := ExpandPolicyConditions(d)
	if err != nil {
		return nil, err
	}

	appConnectorGroups := expandCommonAppConnectorGroups(d)
	appServerGroups := expandCommonServerGroups(d)

	log.Printf("[DEBUG] Expanded app connector groups: %+v", appConnectorGroups)
	log.Printf("[DEBUG] Expanded server groups: %+v", appServerGroups)

	return &policysetcontroller.PolicyRule{
		ID:                 d.Get("id").(string),
		Name:               d.Get("name").(string),
		Description:        d.Get("description").(string),
		Action:             d.Get("action").(string),
		ActionID:           d.Get("action_id").(string),
		BypassDefaultRule:  d.Get("bypass_default_rule").(bool),
		CustomMsg:          d.Get("custom_msg").(string),
		DefaultRule:        d.Get("default_rule").(bool),
		Operator:           d.Get("operator").(string),
		PolicySetID:        policySetID,
		PolicyType:         d.Get("policy_type").(string),
		Priority:           d.Get("priority").(string),
		MicroTenantID:      d.Get("microtenant_id").(string),
		LSSDefaultRule:     d.Get("lss_default_rule").(bool),
		Conditions:         conditions,
		AppServerGroups:    appServerGroups,
		AppConnectorGroups: appConnectorGroups,
	}, nil
}

func expandCommonAppConnectorGroups(d *schema.ResourceData) []policysetcontroller.AppConnectorGroup {
	appConnectorGroupsInterface, ok := d.GetOk("app_connector_groups")
	if !ok {
		log.Printf("[DEBUG] No app connector groups found in resource data")
		return []policysetcontroller.AppConnectorGroup{}
	}

	log.Printf("[DEBUG] App connector groups raw data: %+v", appConnectorGroupsInterface)

	appConnectorGroupsList := appConnectorGroupsInterface.([]interface{})
	if len(appConnectorGroupsList) == 0 {
		return []policysetcontroller.AppConnectorGroup{}
	}

	var result []policysetcontroller.AppConnectorGroup
	for _, group := range appConnectorGroupsList {
		groupMap := group.(map[string]interface{})
		if idList, ok := groupMap["id"].([]interface{}); ok {
			for _, id := range idList {
				if strID, ok := id.(string); ok {
					result = append(result, policysetcontroller.AppConnectorGroup{
						ID: strID,
					})
				}
			}
		}
	}

	log.Printf("[DEBUG] Expanded app connector groups: %+v", result)
	return result
}

func expandCommonServerGroups(d *schema.ResourceData) []policysetcontroller.ServerGroup {
	serverGroupsInterface, ok := d.GetOk("app_server_groups")
	if !ok {
		log.Printf("[DEBUG] No server groups found in resource data")
		return []policysetcontroller.ServerGroup{}
	}

	log.Printf("[DEBUG] Server groups raw data: %+v", serverGroupsInterface)

	serverGroupsList := serverGroupsInterface.([]interface{})
	if len(serverGroupsList) == 0 {
		return []policysetcontroller.ServerGroup{}
	}

	var result []policysetcontroller.ServerGroup
	for _, group := range serverGroupsList {
		groupMap := group.(map[string]interface{})
		if idList, ok := groupMap["id"].([]interface{}); ok {
			for _, id := range idList {
				if strID, ok := id.(string); ok {
					result = append(result, policysetcontroller.ServerGroup{
						ID: strID,
					})
				}
			}
		}
	}

	log.Printf("[DEBUG] Expanded server groups: %+v", result)
	return result
}

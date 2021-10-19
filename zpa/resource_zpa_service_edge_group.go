package zpa

import (
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/willguibr/terraform-provider-zpa/gozscaler/client"
	"github.com/willguibr/terraform-provider-zpa/gozscaler/serviceedgegroup"
)

func resourceServiceEdgeGroup() *schema.Resource {
	return &schema.Resource{
		Create:   resourceServiceEdgeGroupCreate,
		Read:     resourceServiceEdgeGroupRead,
		Update:   resourceServiceEdgeGroupUpdate,
		Delete:   resourceServiceEdgeGroupDelete,
		Importer: &schema.ResourceImporter{},

		Schema: map[string]*schema.Schema{
			"id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the Service Edge Group.",
			},
			"city_country": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"country_code": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the Service Edge Group.",
			},
			"enabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Whether this Service Edge Group is enabled or not.",
			},
			"is_public": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     false,
				Description: "Enable or disable public access for the Service Edge Group.",
				ValidateFunc: validation.StringInSlice([]string{
					"DEFAULT",
					"TRUE",
					"FALSE",
				}, false),
			},
			"latitude": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Latitude for the Service Edge Group.",
			},
			"location": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Location for the Service Edge Group.",
			},
			"longitude": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Longitude for the Service Edge Group.",
			},
			"override_version_profile": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Whether the default version profile of the App Connector Group is applied or overridden.",
			},
			"upgrade_day": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "SUNDAY",
				Description: "Service Edges in this group will attempt to update to a newer version of the software during this specified day.",
			},
			"upgrade_time_in_secs": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "66600",
				Description: "Service Edges in this group will attempt to update to a newer version of the software during this specified time.",
			},
			"version_profile_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "ID of the version profile. To learn more",
			},
		},
	}
}

func resourceServiceEdgeGroupCreate(d *schema.ResourceData, m interface{}) error {
	zClient := m.(*Client)

	req := expandServiceEdgeGroup(d)
	log.Printf("[INFO] Creating zpa service edge group with request\n%+v\n", req)

	resp, _, err := zClient.serviceedgegroup.Create(req)
	if err != nil {
		return err
	}
	log.Printf("[INFO] Created service edge group request. ID: %v\n", resp)
	d.SetId(resp.ID)

	return resourceServiceEdgeGroupRead(d, m)
}

func resourceServiceEdgeGroupRead(d *schema.ResourceData, m interface{}) error {
	zClient := m.(*Client)

	resp, _, err := zClient.serviceedgegroup.Get(d.Id())
	if err != nil {
		if err.(*client.ErrorResponse).IsObjectNotFound() {
			log.Printf("[WARN] Removing service edge group %s from state because it no longer exists in ZPA", d.Id())
			d.SetId("")
			return nil
		}

		return err
	}

	log.Printf("[INFO] Getting service edge group:\n%+v\n", resp)
	_ = d.Set("name", resp.Name)
	_ = d.Set("city_country", resp.CityCountry)
	_ = d.Set("country_code", resp.CountryCode)
	_ = d.Set("description", resp.Description)
	_ = d.Set("enabled", resp.Enabled)
	_ = d.Set("latitude", resp.Latitude)
	_ = d.Set("longitude", resp.Longitude)
	_ = d.Set("location", resp.Location)
	_ = d.Set("upgrade_day", resp.UpgradeDay)
	_ = d.Set("upgrade_time_in_secs", resp.UpgradeTimeInSecs)
	_ = d.Set("override_version_profile", resp.OverrideVersionProfile)
	_ = d.Set("version_profile_id", resp.VersionProfileID)
	_ = d.Set("version_profile_name", resp.VersionProfileName)
	return nil

}

func resourceServiceEdgeGroupUpdate(d *schema.ResourceData, m interface{}) error {
	zClient := m.(*Client)

	id := d.Id()
	log.Printf("[INFO] Updating service edge group ID: %v\n", id)
	req := expandServiceEdgeGroup(d)

	if _, err := zClient.serviceedgegroup.Update(id, &req); err != nil {
		return err
	}

	return resourceServiceEdgeGroupRead(d, m)
}

func resourceServiceEdgeGroupDelete(d *schema.ResourceData, m interface{}) error {
	zClient := m.(*Client)

	log.Printf("[INFO] Deleting service edge group ID: %v\n", d.Id())

	if _, err := zClient.serviceedgegroup.Delete(d.Id()); err != nil {
		return err
	}
	d.SetId("")
	log.Printf("[INFO] service edge group deleted")
	return nil
}

func expandServiceEdgeGroup(d *schema.ResourceData) serviceedgegroup.ServiceEdgeGroup {
	serviceEdgeGroup := serviceedgegroup.ServiceEdgeGroup{
		ID:                     d.Get("id").(string),
		Name:                   d.Get("name").(string),
		CityCountry:            d.Get("city_country").(string),
		CountryCode:            d.Get("country_code").(string),
		Description:            d.Get("description").(string),
		Enabled:                d.Get("enabled").(bool),
		IsPublic:               d.Get("is_public").(string),
		Latitude:               d.Get("latitude").(string),
		Location:               d.Get("location").(string),
		Longitude:              d.Get("longitude").(string),
		OverrideVersionProfile: d.Get("override_version_profile").(bool),
		UpgradeDay:             d.Get("upgrade_day").(string),
		UpgradeTimeInSecs:      d.Get("upgrade_time_in_secs").(string),
	}
	return serviceEdgeGroup
}

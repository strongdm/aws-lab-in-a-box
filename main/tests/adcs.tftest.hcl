#--------------------------------------------------------------
# ADCS/NDES Wiring Tests
#
# Plan-only coverage for the create_adcs feature flag: the module is
# skipped when the flag is off, wires up from module.dc when both the
# flag and create_domain_controller are on, and fails the plan with an
# explicit message instead of passing null credentials into the module
# when the domain controller is missing or var.name is too long for the
# computer name ADCS derives from it.
#
# Every run uses command = plan. terraform_data.dc_ready carries a
# local-exec that shells out to the real sdm CLI; an apply-mode run
# would fire a credentialed call against a mocked resource ID.
#--------------------------------------------------------------

variables {
  name        = "probe"
  tagset      = { environment = "test" }
  secretkey   = "sdm-owner"
  secretvalue = "test@example.com"
  vpc         = null

  create_eks               = false
  create_rds_postgresql    = false
  create_docdb             = false
  create_domain_controller = false
  create_windows_target    = false
  create_linux_target      = false
  create_aws_ro            = false
  create_aws_s3ro          = false
  create_aws_s3full        = false
  create_aws_gluefull      = false
  create_managedsecrets    = false
  create_hcvault           = false
  create_lab_access        = false
  create_adcs              = false
  run_healthchecks         = false
}

mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = {
      names = ["us-east-2a", "us-east-2b", "us-east-2c"]
    }
  }

  mock_data "aws_ami" {
    defaults = {
      id = "ami-0123456789abcdef0"
    }
  }
}

mock_provider "sdm" {}
mock_provider "external" {}

mock_provider "env" {
  mock_data "env_var" {
    defaults = {
      value = "api.strongdm.com:443"
    }
  }
}

run "adcs_disabled_by_default" {
  command = plan

  assert {
    condition     = length(module.adcs) == 0
    error_message = "module.adcs should not be created when create_adcs is false"
  }

  assert {
    condition     = output.ndes_url == null
    error_message = "ndes_url should be null when create_adcs is false"
  }

  assert {
    condition     = output.adcs_fqdn == null
    error_message = "adcs_fqdn should be null when create_adcs is false"
  }
}

run "adcs_wired_from_dc" {
  command = plan

  variables {
    create_domain_controller = true
    create_adcs              = true
  }

  # Sentinel outputs for module.dc. Mocking or override_data on
  # data.sdm_rdp_ca_pubkey still leaves public_key null (it is
  # schema-optional, not computed), which fails dc/dc.tf's
  # base64encode(var.rdpca). Overriding the whole module sidesteps that
  # landmine and proves module.adcs really is wired from module.dc.
  override_module {
    target = module.dc[0]
    outputs = {
      key_name           = "probe-key"
      dc_ip              = "10.0.1.10"
      dc_fqdn            = "dc1.probe.local"
      dc_username        = "administrator"
      dc_password        = "sentinel-dc-pw"
      domain_admin       = "domainadmin"
      domain_password    = "sentinel-domain-pw!"
      svc_ndes_password  = "sentinel-ndes-pw"
      svc_relay_username = "svc-sdm-relay"
      svc_relay_password = "sentinel-relay-pw"
      thistagset         = { environment = "test" }
      private_key_pem    = "sentinel-private-key"
      instance_id        = "i-0123456789abcdef0"
    }
  }

  assert {
    condition     = length(module.adcs) == 1
    error_message = "module.adcs should be created when create_adcs and create_domain_controller are both true"
  }

  assert {
    condition     = length(terraform_data.dc_ready) == 1
    error_message = "dc_ready must widen to gate create_adcs, not just create_windows_target"
  }

  assert {
    condition     = output.adcs_fqdn == "probe-adcs.probe.local"
    error_message = "adcs_fqdn should be derived from var.name"
  }

  assert {
    condition     = output.ndes_url == "https://probe-adcs.probe.local/certsrv/mscep/mscep.dll"
    error_message = "ndes_url should be derived from var.name"
  }

  assert {
    condition     = module.adcs[0].sdm_adcs_user == "svc-sdm-relay@probe.local"
    error_message = "sdm_adcs_user should be derived from var.name"
  }

  # The installer authenticates as this account, and the DC creates domainadmin
  # rather than the built-in Administrator the module defaults to. Without the
  # wiring this output reads "Administrator@probe.local" and the domain join
  # fails ten minutes into a deployment, visible only in C:\bootstrap.log.
  assert {
    condition     = module.adcs[0].domain_admin_user == "domainadmin@probe.local"
    error_message = "domain_admin_user must flow from module.dc: the DC creates domainadmin, not Administrator"
  }

  assert {
    condition     = module.adcs[0].sdm_adcs_password == "sentinel-relay-pw"
    error_message = "svc_relay_password must flow from module.dc into module.adcs"
  }
}

run "adcs_requires_domain_controller" {
  command = plan

  variables {
    create_domain_controller = false
    create_adcs              = true
  }

  expect_failures = [terraform_data.adcs_requires_dc]
}

run "adcs_requires_short_name" {
  command = plan

  variables {
    name                     = "PartnerTraining"
    create_domain_controller = true
    create_adcs              = true
  }

  override_module {
    target = module.dc[0]
    outputs = {
      key_name           = "probe-key"
      dc_ip              = "10.0.1.10"
      dc_fqdn            = "dc1.probe.local"
      dc_username        = "administrator"
      dc_password        = "sentinel-dc-pw"
      domain_admin       = "domainadmin"
      domain_password    = "sentinel-domain-pw!"
      svc_ndes_password  = "sentinel-ndes-pw"
      svc_relay_username = "svc-sdm-relay"
      svc_relay_password = "sentinel-relay-pw"
      thistagset         = { environment = "test" }
      private_key_pem    = "sentinel-private-key"
      instance_id        = "i-0123456789abcdef0"
    }
  }

  expect_failures = [terraform_data.adcs_requires_dc]
}

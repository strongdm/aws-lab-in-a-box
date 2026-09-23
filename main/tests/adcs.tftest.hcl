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

run "adcs_credentials_default_to_relay" {
  command = plan

  # Pinned explicitly (matching its own default) so a developer's
  # gitignored terraform.tfvars cannot silently change which node this
  # run expects to carry the credentials.
  variables {
    create_domain_controller = true
    create_adcs              = true
    adcs_credentials_node    = "relay"
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

  # aws_instance.relay.user_data is unknown at plan time (it embeds
  # sdm_node.relay.relay[0].token, a computed attribute mock_provider does
  # not populate), so this asserts on the locals fed into templatefile()
  # instead - the wiring itself, fully known at plan time and with no new
  # output to leak the password through.
  assert {
    condition     = local.adcs_relay_user == "svc-sdm-relay@probe.local"
    error_message = "the relay should carry SDM_ADCS_USER by default"
  }

  assert {
    condition     = local.adcs_relay_password == "sentinel-relay-pw"
    error_message = "the relay should carry a non-empty SDM_ADCS_PW by default"
  }
  # Renders the template from the real call-site maps, so blanking adcs_user in
  # relay.tf fails this assertion. merge() replaces the relay token, the only
  # value unknown at plan time.
  assert {
    condition = strcontains(
      templatefile("${path.module}/gw-provision.tpl", merge(local.relay_provision_vars, { sdm_relay_token = "probe-token" })),
      "SDM_ADCS_USER=svc-sdm-relay@probe.local"
    )
    error_message = "the relay's rendered user data should set SDM_ADCS_USER"
  }

  assert {
    condition = !strcontains(
      templatefile("${path.module}/gw-provision.tpl", merge(local.gateway_provision_vars, { sdm_relay_token = "probe-token" })),
      "SDM_ADCS_USER"
    )
    error_message = "the gateway must not carry the credentials when the relay is the chosen node"
  }


  assert {
    condition     = local.adcs_gateway_user == "" && local.adcs_gateway_password == ""
    error_message = "the gateway should carry no ADCS credentials while adcs_credentials_node is \"relay\""
  }

  # The locals above prove the selector logic, but say nothing about what
  # actually lands in the rendered provisioning script. templatefile()
  # itself is known at plan time (unlike aws_instance.relay.user_data,
  # which embeds the unknown relay token), so render it directly with the
  # same locals the real call sites pass, and check the %{ if adcs_user }
  # block and its shell quoting.
  assert {
    condition = strcontains(templatefile("${path.module}/gw-provision.tpl", {
      sdm_relay_token = "tok", target_user = "ubuntu", sdm_domain = "",
      create_hcvault  = false, vault_version = "", vault_url = "",
      aws_region      = "us-east-2",
      adcs_user       = local.adcs_relay_user, adcs_password = local.adcs_relay_password,
    }), "SDM_ADCS_USER=svc-sdm-relay@probe.local")
    error_message = "the relay's rendered user data must set SDM_ADCS_USER by default"
  }

  assert {
    condition = strcontains(templatefile("${path.module}/gw-provision.tpl", {
      sdm_relay_token = "tok", target_user = "ubuntu", sdm_domain = "",
      create_hcvault  = false, vault_version = "", vault_url = "",
      aws_region      = "us-east-2",
      adcs_user       = local.adcs_relay_user, adcs_password = local.adcs_relay_password,
    }), "SDM_ADCS_PW=\"sentinel-relay-pw\"")
    error_message = "the relay's rendered user data must set a non-empty, quoted SDM_ADCS_PW by default"
  }

  assert {
    condition = !strcontains(templatefile("${path.module}/gw-provision.tpl", {
      sdm_relay_token = "tok", target_user = "ubuntu", sdm_domain = "",
      create_hcvault  = false, vault_version = "", vault_url = "",
      aws_region      = "us-east-2",
      adcs_user       = local.adcs_gateway_user, adcs_password = local.adcs_gateway_password,
    }), "SDM_ADCS_USER")
    error_message = "the gateway's rendered user data must not set SDM_ADCS_USER while adcs_credentials_node is \"relay\""
  }
}

run "adcs_credentials_absent_when_disabled" {
  command = plan

  # create_adcs = false (the suite default): no ADCS credentials on either
  # node, regardless of adcs_credentials_node.
  variables {
    adcs_credentials_node = "relay"
  }

  assert {
    condition     = local.adcs_relay_user == "" && local.adcs_relay_password == ""
    error_message = "the relay should carry no ADCS credentials when create_adcs is false"
  }

  assert {
    condition     = local.adcs_gateway_user == "" && local.adcs_gateway_password == ""
    error_message = "the gateway should carry no ADCS credentials when create_adcs is false"
  }

  assert {
    condition = !strcontains(
      templatefile("${path.module}/gw-provision.tpl", merge(local.relay_provision_vars, { sdm_relay_token = "probe-token" })),
      "SDM_ADCS_USER"
    )
    error_message = "the rendered user data must not contain SDM_ADCS_USER when create_adcs is false"
  }

  assert {
    condition = !strcontains(templatefile("${path.module}/gw-provision.tpl", {
      sdm_relay_token = "tok", target_user = "ubuntu", sdm_domain = "",
      create_hcvault  = false, vault_version = "", vault_url = "",
      aws_region      = "us-east-2",
      adcs_user       = local.adcs_relay_user, adcs_password = local.adcs_relay_password,
    }), "SDM_ADCS_PW")
    error_message = "the rendered user data must not contain SDM_ADCS_PW when create_adcs is false"
  }
}

run "adcs_credentials_move_to_gateway" {
  command = plan

  variables {
    create_domain_controller = true
    create_adcs              = true
    adcs_credentials_node    = "gateway"
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

  assert {
    condition     = local.adcs_gateway_user == "svc-sdm-relay@probe.local"
    error_message = "setting adcs_credentials_node to \"gateway\" should move SDM_ADCS_USER there"
  }

  assert {
    condition     = local.adcs_gateway_password == "sentinel-relay-pw"
    error_message = "setting adcs_credentials_node to \"gateway\" should move SDM_ADCS_PW there"
  }

  assert {
    condition     = local.adcs_relay_user == "" && local.adcs_relay_password == ""
    error_message = "moving the credentials to the gateway should leave the relay's unchanged (absent)"
  }

  # Same real-call-site render as the relay case, in the opposite direction.
  assert {
    condition = strcontains(
      templatefile("${path.module}/gw-provision.tpl", merge(local.gateway_provision_vars, { sdm_relay_token = "probe-token" })),
      "SDM_ADCS_USER=svc-sdm-relay@probe.local"
    )
    error_message = "the gateway's rendered user data should set SDM_ADCS_USER when it is the chosen node"
  }

  assert {
    condition = !strcontains(
      templatefile("${path.module}/gw-provision.tpl", merge(local.relay_provision_vars, { sdm_relay_token = "probe-token" })),
      "SDM_ADCS_USER"
    )
    error_message = "the relay must not carry the credentials once they move to the gateway"
  }

  assert {
    condition = strcontains(templatefile("${path.module}/gw-provision.tpl", {
      sdm_relay_token = "tok", target_user = "ubuntu", sdm_domain = "",
      create_hcvault  = false, vault_version = "", vault_url = "",
      aws_region      = "us-east-2",
      adcs_user       = local.adcs_gateway_user, adcs_password = local.adcs_gateway_password,
    }), "SDM_ADCS_USER=svc-sdm-relay@probe.local")
    error_message = "setting adcs_credentials_node to \"gateway\" should put SDM_ADCS_USER in the gateway's rendered user data"
  }

  assert {
    condition = strcontains(templatefile("${path.module}/gw-provision.tpl", {
      sdm_relay_token = "tok", target_user = "ubuntu", sdm_domain = "",
      create_hcvault  = false, vault_version = "", vault_url = "",
      aws_region      = "us-east-2",
      adcs_user       = local.adcs_gateway_user, adcs_password = local.adcs_gateway_password,
    }), "SDM_ADCS_PW=\"sentinel-relay-pw\"")
    error_message = "setting adcs_credentials_node to \"gateway\" should put SDM_ADCS_PW in the gateway's rendered user data"
  }

  assert {
    condition = !strcontains(templatefile("${path.module}/gw-provision.tpl", {
      sdm_relay_token = "tok", target_user = "ubuntu", sdm_domain = "",
      create_hcvault  = false, vault_version = "", vault_url = "",
      aws_region      = "us-east-2",
      adcs_user       = local.adcs_relay_user, adcs_password = local.adcs_relay_password,
    }), "SDM_ADCS_USER")
    error_message = "moving the credentials to the gateway should leave the relay's rendered user data without SDM_ADCS_USER"
  }
}

run "adcs_credentials_node_rejects_invalid_value" {
  command = plan

  variables {
    adcs_credentials_node = "bogus"
  }

  expect_failures = [var.adcs_credentials_node]
}

run "adcs_requires_domain_controller" {
  command = plan

  variables {
    create_domain_controller = false
    create_adcs              = true
  }

  expect_failures = [terraform_data.adcs_requires_dc]
}

run "adcs_credentials_case_folds_domain" {
  command = plan

  # var.name flows into the UPN two ways: the DC creates the account with
  # its original casing, but adcs/variables.tf's domain_fqdn (and this
  # module's local.adcs_user) lower-cases it, because AD UPN lookup is
  # case-insensitive. A mixed-case name here, matching PartnerTraining's
  # style in terraform.tfvars.example but short enough to pass the NetBIOS
  # guard, pins that the lower() stays in place.
  variables {
    name                     = "Probe"
    create_domain_controller = true
    create_adcs              = true
    adcs_credentials_node    = "relay"
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

  assert {
    condition     = local.adcs_relay_user == "svc-sdm-relay@probe.local"
    error_message = "SDM_ADCS_USER must lower-case a mixed-case var.name, matching adcs/variables.tf's domain_fqdn"
  }
}

# Regression guard for a whitespace bug caught in review: the %{ if
# adcs_user != "" } block must contribute nothing at all to the render when
# adcs_user is "", not even a stray blank line. aws_instance.relay and
# aws_instance.gateway both set user_data_replace_on_change = true, so any
# byte of drift in the disabled render would replace both instances on the
# next apply for every already-deployed lab that has create_adcs = false -
# and since StrongDM relay/gateway tokens are single-use, the replaced
# instance would boot with an already-consumed token and never register.
# These lengths were measured against the template as it stood immediately
# before the ADCS block was added, with create_hcvault both off and on, so
# a future edit that reintroduces stray whitespace on the disabled path
# fails here instead of surfacing as a silent token-consuming replacement.
run "adcs_disabled_render_is_byte_for_byte_unchanged" {
  command = plan

  assert {
    condition = length(templatefile("${path.module}/gw-provision.tpl", {
      sdm_relay_token = "tok", target_user = "ubuntu", sdm_domain = "",
      create_hcvault  = false, vault_version = "", vault_url = "",
      aws_region      = "us-east-2",
      adcs_user       = "", adcs_password = "",
    })) == 1061
    error_message = "with create_hcvault off, disabling ADCS must render exactly the same 1061 characters as before the ADCS block existed"
  }

  assert {
    condition = length(templatefile("${path.module}/gw-provision.tpl", {
      sdm_relay_token = "tok", target_user = "ubuntu", sdm_domain = "",
      create_hcvault  = true, vault_version = "1.15.0", vault_url = "https://vault.example.com:8200",
      aws_region      = "us-east-2",
      adcs_user       = "", adcs_password = "",
    })) == 4107
    error_message = "with create_hcvault on, disabling ADCS must render exactly the same 4107 characters as before the ADCS block existed"
  }
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

# Deliberately does NOT pin adcs_credentials_node: this run exists to hold the
# default itself, which every other run pins over. If a developer's gitignored
# terraform.tfvars sets the variable, this run failing is the intended signal.
run "adcs_credentials_node_defaults_to_relay" {
  command = plan

  variables {
    create_domain_controller = false
    create_adcs              = false
  }

  assert {
    condition     = var.adcs_credentials_node == "relay"
    error_message = "adcs_credentials_node must default to the relay: the gateway cannot reach the private-subnet ADCS server"
  }
}

# Packer AMI Support - Module Enhancement

## Overview

The DC module now supports **dual-mode operation** to enable faster deployments using Packer-built AMIs.

## Changes Made

### 1. New Variable: `use_packer_ami`

**File**: `variables.tf`

```hcl
variable "use_packer_ami" {
  description = "Set to true if using a Packer-built AMI with pre-installed ADDS/DNS features..."
  type        = bool
  default     = false
}
```

**Default**: `false` (maintains backward compatibility - existing users see no change)

### 2. Dynamic Script Selection

**File**: `dc.tf` (lines 57-60)

```hcl
# Select the appropriate installation script based on AMI type
install_script_template = var.use_packer_ami ?
  "${path.module}/install-dc-from-ami.ps1.tpl" :
  "${path.module}/install-dc.ps1.tpl"
```

**Logic**:
- If `use_packer_ami = false` → Use `install-dc.ps1.tpl` (existing behavior, full installation)
- If `use_packer_ami = true` → Use `install-dc-from-ami.ps1.tpl` (optimized for Packer AMI)

### 3. New Installation Script

**File**: `install-dc-from-ami.ps1.tpl` (new file)

Optimized script that:
- ✅ Skips hostname rename (not required for DC)
- ✅ Skips ADDS/DNS feature installation (pre-installed in AMI)
- ✅ Uses exponential backoff for service waits
- ✅ Reduces scheduled task delay from 5 min → 2 min
- ✅ Removes unnecessary wait times

**Result**: ~11 minute deployment vs. ~18-25 minutes

### 4. Updated Documentation

**File**: `README.md`

Added sections for:
- Configuration examples for both modes
- Installation process comparison
- Packer AMI building instructions
- Performance metrics

## Backward Compatibility

✅ **100% Backward Compatible**

- Default value: `use_packer_ami = false`
- Existing module calls work unchanged
- No breaking changes to variables or outputs
- Both installation scripts use identical template variables

## Usage

### Existing Behavior (No Changes Required)

```hcl
module "dc" {
  source    = "github.com/strongdm/aws-lab-in-a-box.git//dc?ref=2.1.1"
  ami       = data.aws_ami.windows.id
  tagset    = var.tagset
  name      = var.name
  subnet_id = var.subnet_id
  sg        = var.sg
  rdpca     = var.rdpca

  # use_packer_ami defaults to false - no change needed
}
```

### New Optimized Behavior (Opt-In)

```hcl
module "dc" {
  source         = "github.com/strongdm/aws-lab-in-a-box.git//dc?ref=2.1.1"
  ami            = data.aws_ami.packer_dc.id  # Packer-built AMI
  use_packer_ami = true                        # Enable optimization
  tagset         = var.tagset
  name           = var.name
  subnet_id      = var.subnet_id
  sg             = var.sg
  rdpca          = var.rdpca
}
```

## Performance Impact

| Metric | Vanilla (default) | Packer AMI | Improvement |
|--------|------------------|------------|-------------|
| **Deployment Time** | ~18-25 min | ~11 min | **-56%** |
| **Reboots Required** | 2 | 1 | **-50%** |
| **Feature Install Time** | ~5-7 min | 0 min (pre-installed) | **-100%** |

## Testing

### Test Case 1: Default Behavior (Vanilla AMI)
```hcl
use_packer_ami = false  # or omit (default)
ami = data.aws_ami.windows.id
```
✅ **Expected**: Full installation, ~18-25 min, identical to previous behavior

### Test Case 2: Packer AMI Mode
```hcl
use_packer_ami = true
ami = data.aws_ami.packer_dc.id
```
✅ **Expected**: Optimized installation, ~11 min, features pre-installed

### Test Case 3: Wrong Configuration (Handled Gracefully)
```hcl
use_packer_ami = true
ami = data.aws_ami.windows.id  # Wrong AMI (vanilla instead of Packer)
```
✅ **Expected**: Script detects missing features and falls back to installing them

## Files Modified

1. **variables.tf** - Added `use_packer_ami` variable
2. **dc.tf** - Added conditional script selection logic
3. **README.md** - Updated with dual-mode documentation
4. **install-dc-from-ami.ps1.tpl** - New optimized installation script (added)
5. **PACKER-AMI-SUPPORT.md** - This document (added)

## Files NOT Modified

- ✅ `outputs.tf` - No changes
- ✅ `install-dc.ps1.tpl` - No changes (preserved for vanilla AMI mode)
- ✅ IAM resources - No changes
- ✅ S3 bucket configuration - No changes

## Integration with Europa Project

The europa project can now reference this module and optionally enable Packer AMI mode:

```hcl
module "dc" {
  source = "github.com/strongdm/aws-lab-in-a-box.git//dc?ref=2.1.1"

  ami            = data.aws_ami.ad-sdm-build.id  # From amis.tf
  use_packer_ami = true                          # Enable optimization

  # ... other variables
}
```

See `europa/terraform/bootstrap/DC-MODULE-USAGE.md` for detailed integration examples.

## Packer Template Reference

The Packer template that creates the optimized AMI is located at:
- **Location**: `europa/packer/windows-dc-base.pkr.hcl`
- **Build time**: ~20-30 minutes (one-time)
- **AMI name pattern**: `strongdm-windows-dc-base-<timestamp>`
- **Features installed**: ADDS, DNS, PowerShell modules, AWS Tools

## Version Compatibility

| Module Version | Supports Packer AMI | Notes |
|----------------|---------------------|-------|
| < 2.1.1 | ❌ No | Only supports vanilla Windows Server |
| >= 2.1.1 | ✅ Yes | Dual-mode support (opt-in via variable) |

## Rollback Procedure

If issues arise with Packer AMI mode:

1. Set `use_packer_ami = false` in module call
2. Change `ami` back to vanilla Windows Server AMI
3. Module will use original installation script
4. No data loss - deployment will just take longer

## Support

For issues or questions:
- Check module README: `aws-lab-in-a-box/dc/README.md`
- Review Packer template: `europa/packer/windows-dc-base.pkr.hcl`
- See europa integration guide: `europa/terraform/bootstrap/DC-MODULE-USAGE.md`
- Full session context: `europa/packer/SESSION-SUMMARY.md`

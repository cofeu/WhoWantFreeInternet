provider "oci" {
  region = var.region
  # Credentials come from the standard OCI SDK chain:
  #   TF_VAR_tenancy_ocid / config file / env (OCI_CLI_*).
}
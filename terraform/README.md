# WWFI on OCI with Terraform

This configuration provisions the full WWFI runtime on Oracle Cloud
Infrastructure in one `terraform apply`:

- **VCN** with an internet gateway and route table
- **Public subnet** with a security list (SSH, HTTPS/SNI, HTTP-for-ACME, DNS 53, metrics 9090)
- **Compute instance** (Ubuntu) whose cloud-init bootstraps the node:
  clone repo → `scripts/install.sh` → register `wwfi-dns.service` →
  generate nginx reverse proxy sites.

## Usage

```bash
cd terraform

export TF_VAR_tenancy_ocid="ocid1.tenancy.oc1...."
export TF_VAR_compartment_ocid="ocid1.compartment.oc1...."
export TF_VAR_ssh_public_key="$(cat ~/.ssh/id_ed25519.pub)"

terraform init
terraform plan
terraform apply -auto-approve

# connect
ssh -i ~/.ssh/id_ed25519 ubuntu@$(terraform output -raw public_ip)
```

Optional overrides:

```bash
TF_VAR_region="eu-frankfurt-1"
TF_VAR_shape="VM.Standard.E4.Flex"          # + TF_VAR_flex_shape_ocpus
TF_VAR_wwfi_repo="https://github.com/YOU/WhoWantFreeInternet.git"
```

After boot, cloud-init runs `scripts/generate_reverse_proxy.sh` so
`demo.local` and `shop.local` resolve on the node. Point real DNS at the
instance's public IP or use `curl --resolve demo.local:443:<IP>`.

## Security list

| Port | Protocol | Purpose |
|------|----------|---------|
| 22   | TCP      | SSH |
| 80   | TCP      | ACME HTTP-01 challenge |
| 443  | TCP      | HTTPS / SNI multi-domain |
| 53   | TCP/UDP  | local DNS |
| 9090 | TCP      | Prometheus metrics (lock this down in production) |

## Notes

- Cloud-init user-data is the repository's `cloud-init.yaml`
  (`${module}/../cloud-init.yaml`), with the repo URL injected at apply time.
- A private `oci_core_subnet` + `nat_gateway` example is easy to add; the
  security list already gives you a fail-closed default (only the listed
  ports are opened).
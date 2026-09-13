data "oci_identity_availability_domains" "ads" {
  compartment_id = var.compartment_ocid
}

data "oci_core_images" "wwfi_images" {
  compartment_id           = var.compartment_ocid
  operating_system         = "Canonical Ubuntu"
  operating_system_version = "22.04"
  sort_by                 = "TIMECREATED"
  sort_order              = "DESC"
}

locals {
  ad_name        = var.availability_domain != "" ? var.availability_domain : data.oci_identity_availability_domains.ads.availability_domains[0].name
  image_ocid     = var.image_id != "" ? var.image_id : data.oci_core_images.wwfi_images.images[0].id
  wwfi_user_data = base64encode(
    replace(
      file("${path.module}/../cloud-init.yaml"),
      "https://github.com/USERNAME/WhoWantFreeInternet.git",
      var.wwfi_repo,
    )
  )
}

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

resource "oci_core_vcn" "wwfi" {
  compartment_id = var.compartment_ocid
  cidr_blocks    = [var.vcn_cidr]
  display_name   = "wwfi-vcn"
  dns_label      = "wwfi"
}

resource "oci_core_internet_gateway" "wwfi" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.wwfi.id
  enabled        = true
  display_name   = "wwfi-igw"
}

resource "oci_core_route_table" "wwfi" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.wwfi.id
  display_name   = "wwfi-rt"
  route_rules {
    destination       = "0.0.0.0/0"
    network_entity_id = oci_core_internet_gateway.wwfi.id
  }
}

resource "oci_core_security_list" "wwfi" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.wwfi.id
  display_name   = "wwfi-sl"

  egress_security_rules {
    destination = "0.0.0.0/0"
    protocol    = "all"
  }

  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options { min = 22 max = 22 } # SSH
  }
  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options { min = 443 max = 443 } # HTTPS / SNI
  }
  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options { min = 80 max = 80 } # ACME HTTP-01
  }
  ingress_security_rules {
    protocol = "17"
    source   = "0.0.0.0/0"
    udp_options { min = 53 max = 53 } # DNS
  }
  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options { min = 53 max = 53 } # DNS over TCP
  }
  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options { min = 9090 max = 9090 } # Prometheus metrics
  }
}

resource "oci_core_subnet" "wwfi" {
  compartment_id      = var.compartment_ocid
  vcn_id              = oci_core_vcn.wwfi.id
  cidr_block          = var.subnet_cidr
  route_table_id      = oci_core_route_table.wwfi.id
  security_list_ids   = [oci_core_security_list.wwfi.id]
  display_name        = "wwfi-subnet"
  dns_label           = "wwfisubnet"
  prohibit_public_ip_on_vnic = false
}

# ---------------------------------------------------------------------------
# Compute
# ---------------------------------------------------------------------------

resource "oci_core_instance" "wwfi" {
  compartment_id      = var.compartment_ocid
  availability_domain = local.ad_name
  shape               = var.shape
  display_name        = "wwfi-node-1"

  source_details {
    source_type = "image"
    source_id   = local.image_ocid
  }

  create_vnic_details {
    subnet_id        = oci_core_subnet.wwfi.id
    assign_public_ip = true
    display_name     = "wwfi-vnic"
  }

  metadata = {
    ssh_authorized_keys = var.ssh_public_key
    user_data           = local.wwfi_user_data
  }

  preserve_boot_volume = false
}
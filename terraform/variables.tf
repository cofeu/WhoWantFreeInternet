variable "tenancy_ocid" {
  description = "OCI tenancy OCID"
  type        = string
}

variable "compartment_ocid" {
  description = "Compartment that will host the WWFI instance and network"
  type        = string
}

variable "region" {
  description = "OCI region (e.g. eu-frankfurt-1)"
  type        = string
  default     = "eu-frankfurt-1"
}

variable "shape" {
  description = "Compute shape for the WWFI node"
  type        = string
  default     = "VM.Standard.E2.1.Micro"
}

variable "availability_domain" {
  description = "Availability domain name; left empty to auto-select the first one"
  type        = string
  default     = ""
}

variable "image_id" {
  description = "Oracle Linux / Ubuntu image OCID; empty to auto-select the latest Ubuntu"
  type        = string
  default     = ""
}

variable "ssh_public_key" {
  description = "SSH public key used to log into the instance"
  type        = string
}

variable "vcn_cidr" {
  description = "Virtual cloud network CIDR"
  type        = string
  default     = "10.0.0.0/16"
}

variable "subnet_cidr" {
  description = "Public subnet CIDR where the WWFI instance lives"
  type        = string
  default     = "10.0.1.0/24"
}

variable "wwfi_repo" {
  description = "WWFI repository to clone during cloud-init"
  type        = string
  default     = "https://github.com/USERNAME/WhoWantFreeInternet.git"
}

variable "ipv6_enabled" {
  description = "Whether to also allocate IPv6 to the subnet"
  type        = bool
  default     = false
}
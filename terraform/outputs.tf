output "instance_ocid" {
  value = oci_core_instance.wwfi.id
}

output "public_ip" {
  value = oci_core_instance.wwfi.public_ip
}

output "vcn_id" {
  value = oci_core_vcn.wwfi.id
}

output "subnet_id" {
  value = oci_core_subnet.wwfi.id
}
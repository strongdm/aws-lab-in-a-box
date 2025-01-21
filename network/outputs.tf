output "vpc"{
  value = aws_vpc.main.id
}
output "gateway_subnet" {
  value = aws_subnet.gateway.id
}
output "relay_subnet" {
  value = element(aws_subnet.relay[*].id, 0)
}
output "private_sg" {
  value = aws_security_group.relay.id

}
output "public_sg" {
  value = aws_security_group.gateway.id
}

output "relay_subnet-b" {
  value = element(aws_subnet.relay[*].id, 1)
}

output "relay_subnet-c" {
  value = element(aws_subnet.relay[*].id, 2)
}

import cui_des

des = cui_des.DES('CBC')
key = b'password'
message = b'Hi my name is Andrew.'
result = des.encrypt(message, key)
print(result)

message = b'Hi my name is Andrew'
result = des.encrypt(message, key)
print(result)
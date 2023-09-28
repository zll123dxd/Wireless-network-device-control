# Wireless-network-device-control
network_device is used to control the status of wireless devices, such as modifying mac or starting.
network_device目录下编译可以控制设备的up/down, mac地址

send_msg目录用于模拟AP/STA发送无线帧.
在linux环境下接入无线网卡可以使用.   仅可用于测试
1.beacon 
2.deauthentication
3.disassociate
由于控制帧不加密， 对于wpa3之前类型的ap， 可以模拟AP mac地址发送2/3的帧以达到强制断开STA的目的.
请勿用于违法用途

package main

import (
	"./dogcom"
	"fmt"
)

func main() {
	DogCom := dogcom.DogCom{
		Username:           "20172333",     //用户名，一般为学号
		Password:           "114514",       //密码
		Server:             "10.254.7.4",   //认证服务器
		Mac:                0x3c52823422f9, //MAC地址
		CONTROLCHECKSTATUS: byte(0x20),
		ADAPTERNUM:         byte(0x03),
		HostIP:             "10.253.147.48",
		IPDOG:              byte(0x01),
		HostName:           "fuyumi",
		PrimaryDns:         "202.202.0.33",
		DhcpServer:         "10.253.7.7",
		HostOS:             "Windows 10",
		AUTH_VERSION:       []byte{0x25, 0x00},
		KEEP_ALIVE_VERSION: []byte{0xdc, 0x02},
	}
	for {
		DogCom.Login()
		fmt.Printf("[package_tail]%X \n", DogCom.AUTH_INFO)
		DogCom.EmptySocketBuffer()
		DogCom.HeartBeats1()
		DogCom.HeartBeats2()
	}

}

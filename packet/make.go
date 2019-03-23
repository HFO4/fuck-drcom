package packet

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"strconv"
	"strings"
)

func ljust(usr []byte) [36]byte {
	var arr [36]byte
	if len(usr) >= 36 {
		copy(arr[:], usr[:36])
		return arr
	}
	newArr := make([]byte, 36-len(usr))
	copy(arr[:], append(usr, newArr...))
	return arr
}

func ljustCustom(usr []byte, length int) []byte {
	var arr []byte
	if len(usr) >= length {
		arr = usr[:length]
		return arr
	}
	newArr := make([]byte, length-len(usr))
	arr = append(usr, newArr...)
	return arr
}

func rjust(usr []byte) [6]byte {
	var arr [6]byte
	outIndex := 0
	for index := 0; index < 8; index++ {
		if usr[index] != byte(0x00) {
			copy(arr[outIndex:outIndex+1], usr[index:index+1])
			outIndex++
		}
	}
	return arr
}

//MakeHearbeats2 封装心跳包2
func MakeHearbeats2(svr_num int, tail []byte, pType int, first bool, KEEP_ALIVE_VERSION []byte, host_ip string) []byte {
	var data []byte
	data = append(data, byte(0x07))
	data = append(data, byte(svr_num))
	data = append(data, []byte{0x28, 0x00, 0x0b}...)
	data = append(data, byte(pType))
	if first {
		data = append(data, []byte{0x0f, 0x27}...)
	} else {
		data = append(data, KEEP_ALIVE_VERSION...)
	}
	data = append(data, []byte{0x2f, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)
	data = append(data, tail...)
	data = append(data, []byte{0x00, 0x00, 0x00, 0x00}...)
	if pType == 3 {
		var IPList = make([]byte, 4)
		ips := strings.Split(host_ip, ".")
		for k, v := range ips {
			ipSp, _ := strconv.Atoi(v)
			IPList[k] = byte(ipSp)
		}
		data = append(data, []byte{0x00, 0x00, 0x00, 0x00}...)
		data = append(data, IPList...)
		data = append(data, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)
	} else {
		data = append(data, []byte{
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		}...)
	}
	return data
}

//MakePacket 封装数据包
func MakePacket(salt []byte, usr string, pwd string, mac uint64, CONTROLCHECKSTATUS byte, ADAPTERNUM byte, HostIP string, IPDOG byte, HostName string, dns string, DhcpServer string, HostOS string, authVer []byte) []byte {
	mdSum := md5.Sum(append(append([]byte{0x03, 0x01}, salt...), []byte(pwd)...))
	mdSum2 := md5.Sum(append(append(append([]byte{0x01}, []byte(pwd)...), salt...), []byte{0x00, 0x00, 0x00, 0x00}...))
	var bufMacAddrXORPasswordMD5 = make([]byte, 8)
	mdSumFull := make([]byte, 2)
	binary.BigEndian.PutUint64(bufMacAddrXORPasswordMD5, binary.BigEndian.Uint64(append(mdSumFull, mdSum[:6]...))^mac)

	var HostIPList [4][4]byte
	ips := strings.Split(HostIP, ".")
	for k, v := range ips {
		ipSp, _ := strconv.Atoi(v)
		HostIPList[0][k] = byte(ipSp)
	}

	var DNSList [4]byte
	dnsss := strings.Split(dns, ".")
	for k, v := range dnsss {
		ipSp, _ := strconv.Atoi(v)
		DNSList[k] = byte(ipSp)
	}

	var DHCPList [4]byte
	dhcps := strings.Split(DhcpServer, ".")
	for k, v := range dhcps {
		ipSp, _ := strconv.Atoi(v)
		DHCPList[k] = byte(ipSp)
	}

	var hostByte [32]byte
	hostSlice := ljustCustom([]byte(HostName), 32)
	copy(hostByte[:], hostSlice[:32])

	var osByte [32]byte
	osSlice := ljustCustom([]byte(HostOS), 32)
	copy(osByte[:], osSlice[:32])

	var AuthVer [2]byte
	copy(AuthVer[:], authVer[:2])

	pkt := tagLoginPacket{
		tagDrCOMHeader: [4]byte{
			0x03, 0x01, 0x00, byte(len([]rune(usr)) + 20),
		},
		PasswordMd5:           mdSum,
		Account:               ljust([]byte(usr)),
		ControlCheckStatus:    CONTROLCHECKSTATUS,
		AdapterNum:            ADAPTERNUM,
		MacAddrXORPasswordMD5: rjust(bufMacAddrXORPasswordMD5),
		PasswordMd5_2:         mdSum2,
		HostIPNum:             byte(0x01),
		HostIPList:            HostIPList,
		DogFlag:               IPDOG,
		Unkown2:               [4]byte{0x00, 0x00, 0x00, 0x00},
		HostInfo: tagOSVERSIONINFO{
			HostName:     hostByte,
			DNSIP1:       DNSList,
			DHCPServerIP: DHCPList,
			DNSIP2:       [4]byte{0x00, 0x00, 0x00, 0x00},
			WINSIP1:      [4]byte{0x00, 0x00, 0x00, 0x00},
			WINSIP2:      [4]byte{0x00, 0x00, 0x00, 0x00},
			OSVersion: tagDrCOMOSVERSIONINFO{
				OSVersionInfoSize: [4]byte{0x94, 0x00, 0x00, 0x00},
				MajorVersion:      [4]byte{0x05, 0x00, 0x00, 0x00},
				MinorVersion:      [4]byte{0x01, 0x00, 0x00, 0x00},
				BuildNumber:       [4]byte{0x28, 0x0A, 0x00, 0x00},
				PlatformID:        [4]byte{0x02, 0x00, 0x00, 0x00},
				ServicePack:       osByte,
			},
		},
		DogVersion:          AuthVer,
		tagDrcomAuthExtData: [2]byte{0x02, 0x0c},
	}
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.BigEndian, &pkt)
	if err != nil {
		panic(err)
	}
	halfMd := md5.Sum(append(buf.Bytes()[:97], []byte{0x14, 0x00, 0x07, 0x0b}...))
	var HalfMD5 [8]byte
	copy(HalfMD5[:], halfMd[:8])
	pkt.HalfMD5 = HalfMD5

	bufFinal := &bytes.Buffer{}
	err = binary.Write(bufFinal, binary.BigEndian, &pkt)
	if err != nil {
		panic(err)
	}
	return bufFinal.Bytes()

}

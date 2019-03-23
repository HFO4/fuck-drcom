package dogcom

import (
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"time"

	"../packet"
)

//DogCom DrCom配置
type DogCom struct {
	Username           string
	Password           string
	Server             string
	Mac                uint64
	Con                net.Conn
	Salt               []byte
	CONTROLCHECKSTATUS byte
	ADAPTERNUM         byte
	HostIP             string
	IPDOG              byte
	HostName           string
	PrimaryDns         string
	DhcpServer         string
	HostOS             string
	AUTH_VERSION       []byte
	AUTH_INFO          []byte
	KEEP_ALIVE_VERSION []byte
}

func (dog *DogCom) initUDP() {
	if dog.Con == nil {
		conn, err := net.DialTimeout("udp", dog.Server+":"+strconv.Itoa(61440), time.Duration(5)*time.Second)
		if err != nil {
			fmt.Println("UDP connection failed,", err)
			time.Sleep(time.Duration(2) * time.Second)
			dog.initUDP()
		}
		dog.Con = conn
		fmt.Println("UDP connection init")
	}
}

func (dog *DogCom) challange(randNum int64) ([]byte, error) {
	data := make([]byte, 1024)
	for {
		randNumCheck := uint16(randNum % (0xFFFF))
		bs := make([]byte, 2)
		binary.LittleEndian.PutUint16(bs, randNumCheck)
		payload := []byte{
			0x01, 0x01, bs[0], bs[1], 0x09, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		}
		//fmt.Printf("%x", payload)
		dog.Con.Write(payload)
		dog.Con.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := dog.Con.Read(data)
		if err != nil {
			fmt.Println("[challenge] timeout, retrying...", err)
			time.Sleep(time.Duration(2) * time.Second)
			continue
		}
		fmt.Printf("[challange]recv %X \n", data[:n])
		break
	}

	if data[0] != 0x02 {
		fmt.Println("[challenge] error challenge")
		return nil, errors.New("error challenge")
	}
	return data[4:8], nil
}

//EmptySocketBuffer 清空缓冲区
func (dog *DogCom) EmptySocketBuffer() {
	fmt.Println("starting to empty socket buffer")
	data := make([]byte, 1024)
	for {
		dog.Con.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := dog.Con.Read(data)
		if err != nil {
			fmt.Println("exception in empty_socket_buffer")
			break
		}
		fmt.Printf("recived sth unexpected %X \n", data[:n])
	}

}

func strtWidth(data []byte, start []byte) bool {
	for i := 0; i < 4; i++ {
		if data[i] != start[i] {
			return false
		}
	}
	return true
}

//HeartBeats2 心跳包2
func (dog *DogCom) HeartBeats2() {
	svr_num := 0
	var tail []byte
	heartBeatPacket := packet.MakeHearbeats2(svr_num, []byte{0x00, 0x00, 0x00, 0x00}, 1, true, dog.KEEP_ALIVE_VERSION, dog.HostIP)
	for {
		fmt.Printf("[heartbeats2] send1 %X \n", heartBeatPacket)
		dog.Con.Write(heartBeatPacket)
		data := make([]byte, 1024)
		dog.Con.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _ := dog.Con.Read(data)
		fmt.Printf("[heartbeats2] recv1 %X \n", data[:n])
		if strtWidth(data[:4], []byte{0x07, 0x00, 0x28, 0x00}) || strtWidth(data[:4], []byte{0x07, byte(svr_num), 0x28, 0x00}) {
			break
		} else if data[0] == 0x07 && data[2] == 0x10 {
			fmt.Println("[heartbeats2] recv file, resending..")
			svr_num++
			break
		} else {
			fmt.Printf("[heartbeats2] recv1/unexpected %X \n", data[:n])
		}
	}
	heartBeatPacket = packet.MakeHearbeats2(svr_num, []byte{0x00, 0x00, 0x00, 0x00}, 1, false, dog.KEEP_ALIVE_VERSION, dog.HostIP)
	fmt.Printf("[heartbeats2] send2 %X \n", heartBeatPacket)
	dog.Con.Write(heartBeatPacket)
	data := make([]byte, 1024)
	n := 0
	for {
		dog.Con.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _ = dog.Con.Read(data)
		if data[0] == 0x07 {
			svr_num++
			break
		} else {
			fmt.Printf("[heartbeats2] recv2/unexpected %X \n", data[:n])
		}
	}
	fmt.Printf("[heartbeats2] recv2 %X \n", data[:n])
	tail = data[16:20]
	heartBeatPacket = packet.MakeHearbeats2(svr_num, tail, 3, false, dog.KEEP_ALIVE_VERSION, dog.HostIP)
	fmt.Printf("[heartbeats2] send3 %X \n", heartBeatPacket)
	dog.Con.Write(heartBeatPacket)
	data = make([]byte, 1024)
	for {
		dog.Con.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _ = dog.Con.Read(data)
		if data[0] == 0x07 {
			svr_num++
			break
		} else {
			fmt.Printf("[heartbeats2] recv3/unexpected %X \n", data[:n])
		}
	}
	fmt.Printf("[heartbeats2] recv3 %X \n", data[:n])
	tail = data[16:20]
	fmt.Println("[heartbeats2] heartbeats2 loop was in daemon.")
	i := svr_num
	for {
		time.Sleep(time.Duration(10) * time.Second)
		dog.HeartBeats1()
		heartBeatPacket = packet.MakeHearbeats2(i, tail, 1, false, dog.KEEP_ALIVE_VERSION, dog.HostIP)
		fmt.Printf("[heartbeats2] send %X \n", heartBeatPacket)
		_, err := dog.Con.Write(heartBeatPacket)
		if err != nil {
			break
		}
		err = dog.Con.SetReadDeadline(time.Now().Add(5 * time.Second))
		if err != nil {
			break
		}
		data = make([]byte, 1024)
		n, err = dog.Con.Read(data)
		if err != nil {
			break
		}
		fmt.Printf("[heartbeats2] recv %X \n", data[:n])
		tail = data[16:20]
		heartBeatPacket = packet.MakeHearbeats2(i+1, tail, 3, false, dog.KEEP_ALIVE_VERSION, dog.HostIP)
		_, err = dog.Con.Write(heartBeatPacket)
		if err != nil {
			break
		}
		fmt.Printf("[heartbeats2] send %X \n", heartBeatPacket)
		data = make([]byte, 1024)
		n, err = dog.Con.Read(data)
		if err != nil {
			break
		}
		fmt.Printf("[heartbeats2] recv %X \n", data[:n])
		tail = data[16:20]
		i = (i + 2) % 0xFF
	}
}

//HeartBeats1 心跳包1
func (dog *DogCom) HeartBeats1() {
	timeNow := uint16(time.Now().Unix() % 0xFFFF)
	bs := make([]byte, 2)
	binary.BigEndian.PutUint16(bs, timeNow)
	var data []byte
	data = append(data, []byte{0xff}...)
	md5Sum := md5.Sum(append(append([]byte{0x03, 0x01}, dog.Salt...), []byte(dog.Password)...))
	data = append(data, md5Sum[:]...)
	data = append(data, []byte{0x00, 0x00, 0x00}...)
	data = append(data, dog.AUTH_INFO...)
	data = append(data, bs...)
	data = append(data, []byte{0x00, 0x00, 0x00, 0x00}...)
	fmt.Printf("[heartbeats1] send %X \n", data)
	dog.Con.Write(data)
	recvData := make([]byte, 1024)
	n := 0
	for {
		dog.Con.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, _ = dog.Con.Read(recvData)
		if recvData[0] == 0x07 {
			break
		} else {
			fmt.Printf("[heartbeats1] recv/not expected %X\n", recvData[:n])
		}
	}
	fmt.Printf("[heartbeats1] recv %X\n", recvData[:n])
}

//Login 执行登录
func (dog *DogCom) Login() {
	dog.initUDP()
	for {
		rand.Seed(time.Now().UnixNano())
		randNum := rand.Intn(240) + 15
		salt, _ := dog.challange(time.Now().Unix() + int64(randNum))
		dog.Salt = salt
		loginPacket := packet.MakePacket(dog.Salt, dog.Username, dog.Password, dog.Mac, dog.CONTROLCHECKSTATUS, dog.ADAPTERNUM, dog.HostIP, dog.IPDOG, dog.HostName, dog.PrimaryDns, dog.DhcpServer, dog.HostOS, dog.AUTH_VERSION)
		dog.Con.Write(loginPacket)
		fmt.Printf("[login]send %X \n", loginPacket)
		data := make([]byte, 1024)
		n, err := dog.Con.Read(data)
		if err != nil {
			fmt.Println("[login] recv timeout.", err)
			continue
		}
		fmt.Printf("[login]recv %X \n", data[:n])
		if data[0] == 0x04 {
			fmt.Println("[login] logged in")
			dog.AUTH_INFO = data[23:39]
			break
		} else {
			fmt.Println("[login] login failed.")
			time.Sleep(time.Duration(30) * time.Second)
			continue
		}

	}

}

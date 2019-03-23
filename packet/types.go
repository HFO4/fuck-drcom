package packet

type tagDrCOMOSVERSIONINFO struct {
	OSVersionInfoSize [4]byte
	MajorVersion      [4]byte
	MinorVersion      [4]byte
	BuildNumber       [4]byte
	PlatformID        [4]byte
	ServicePack       [32]byte
	ServicePackEmpty  [96]byte
}

type tagOSVERSIONINFO struct {
	HostName     [32]byte
	DNSIP1       [4]byte
	DHCPServerIP [4]byte
	DNSIP2       [4]byte
	WINSIP1      [4]byte
	WINSIP2      [4]byte
	OSVersion    tagDrCOMOSVERSIONINFO
}

type tagLoginPacket struct {
	tagDrCOMHeader        [4]byte
	PasswordMd5           [16]byte
	Account               [36]byte
	ControlCheckStatus    byte
	AdapterNum            byte
	MacAddrXORPasswordMD5 [6]byte
	PasswordMd5_2         [16]byte
	HostIPNum             byte
	HostIPList            [4][4]byte
	HalfMD5               [8]byte
	DogFlag               byte
	Unkown2               [4]byte
	HostInfo              tagOSVERSIONINFO
	DogVersion            [2]byte
	tagDrcomAuthExtData   [2]byte
}

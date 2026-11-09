// mixia-nmhost 把浏览器扩展接到已解锁的桌面客户端。同一个程序两种身份：
//
//	mixia-nmhost chrome-extension://<id>/   浏览器启动的 native messaging host
//	mixia-nmhost --serve                    Electron 启动的管道服务，stdio 接主进程
//
// 两边都是这个程序，所以管道两端可以互相核对对方的镜像路径。协议见 README.md。
package main

import "os"

const (
	extensionID     = "ikicghdoopckcolomkneepiooaengmep"
	extensionOrigin = "chrome-extension://" + extensionID + "/"
)

func main() {
	switch role(os.Args[1:]) {
	case "serve":
		if serveDesktop(os.Stdin, os.Stdout) != nil {
			os.Exit(1)
		}
	case "host":
		// 浏览器关掉端口时立刻退出，不留下等用户确认的进程
		if runHost(os.Stdin, os.Stdout, dialDesktop, func() { os.Exit(0) }) != nil {
			os.Exit(1)
		}
	default:
		os.Exit(2)
	}
}

// role 决定这次运行的身份。浏览器把调用方的 origin 放在第一个参数：
// 不是钉死的扩展就不干活，这是 allowed_origins 之外的第二道。
func role(args []string) string {
	if len(args) == 0 {
		return ""
	}
	switch args[0] {
	case "--serve":
		return "serve"
	case extensionOrigin:
		return "host"
	}
	return ""
}

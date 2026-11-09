// mixia-hwkey 是密匣桌面端的硬件密钥助手：长驻子进程，stdin/stdout 每行一个 JSON。
// 协议、构建与实测结论见 README.md。
package main

import "os"

func main() {
	if err := serve(os.Stdin, os.Stdout, newBackend()); err != nil {
		os.Exit(1)
	}
}

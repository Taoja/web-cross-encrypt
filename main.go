package main

import (
	cRand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm4"
	"math/rand"
	"syscall/js"
	"time"
)

var kvMap = make(map[string] []byte) // 内存键值对

// 主进程
func main() {
	c := make(chan bool)
	jsEncrypt := js.FuncOf(doEncrypt) // 创建js加密函数
	jsDecrypt := js.FuncOf(doDecrypt) // 创建js解密函数
	js.Global().Set("encrypt", jsEncrypt) // 加密函数赋值给window.encrypt
	js.Global().Set("decrypt", jsDecrypt) // 解密函数赋值给window.decrypt
	<- c
}

// 暴露给js的加密方法
func doEncrypt(_ js.Value, inputs []js.Value) interface{} {
	if len(inputs) == 0 {
		fmt.Printf("请输入需要加密的内容\n")
		return ""
	}
	arg1 := inputs[0].String() // 获取需要加密的字符串
	key := initRandomKey() // 生成随机秘钥
	data := []byte(arg1) // 加密字符串转byte数组
	enc, err := sm4.Sm4Ecb(key, data, true) // 加密
	if err != nil {
		fmt.Printf("错误：%v\n", err)
		return ""
	}
	encB64 := base64.StdEncoding.EncodeToString(enc) // 密文转base64
	keyB64, err2 := encryptKey(key) // 秘钥转base64
	if err2 != nil {
		fmt.Printf("错误：%v\n", err)
		return ""
	}
	return []interface{}{encB64, keyB64} // 输出[密文, 秘钥]
}

// 暴露给js的解密方法
func doDecrypt(_ js.Value, inputs []js.Value) interface{} {
	if len(inputs) < 2 {
		fmt.Printf("参数不全\n")
		return ""
	}
	arg1 := inputs[0].String() // 获取需要解密的base64
	arg2 := inputs[1].String() // 获取加密后的秘钥base64
	key, err0 := getMap(arg2) // 通过内存获取明文sm4秘钥
	if err0 != nil {
		fmt.Printf("错误：%v\n", err0)
		return ""
	}
	data, err := base64.StdEncoding.DecodeString(arg1) // 密文转byte数组
	if err != nil {
		fmt.Printf("错误：%v\n", err)
		return ""
	}
	dec, err1 := sm4.Sm4Ecb(key, data, false) // 解密
	if err1 != nil {
		fmt.Printf("错误：%v\n", err1)
		return ""
	}
	deleteMap(arg2) // 解密完成后删除对应内存
	return string(dec) // 返回解密后的字符串
}

// 生成随机秘钥
func initRandomKey() []byte {
	m := []byte("1234567890qwertyuiopasdfghjklzxcvbnm")
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(36, func(i, j int) { m[i], m[j] = m[j], m[i] })
	return m[0:16]
}

// 使用sm2加密sm4秘钥
func encryptKey(key []byte) (string, error) {
	pubByte, err1 := hex.DecodeString("041bf86ecf5d8699d2")
	if err1 != nil {
		return "", err1
	}
	pub := sm2.Decompress(pubByte)
	enc, err := pub.EncryptAsn1(key,cRand.Reader) //sm2加密
	if err != nil {
		return "", err
	}
	b64 := base64.StdEncoding.EncodeToString(enc)
	setMap(b64, key)
	return b64, nil
}

// 创建sm4秘钥加密后base64与明文秘钥的对应关系
func setMap(keyB64 string, key []byte) {
	kvMap[keyB64] = key
}

// 通过base64秘钥查询明文秘钥
func getMap(keyB64 string) ([]byte, error) {
	key, err := kvMap[keyB64]
	if !err {
		return nil, errors.New("内存键值对检索失败")
	}
	return key, nil
}

func deleteMap(keyB64 string) {
	delete(kvMap, keyB64)
}

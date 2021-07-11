package main

import (
	cRand "crypto/rand"
	"encoding/base64"
	"errors"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm4"
	"github.com/tjfoc/gmsm/x509"
	"math/rand"
	"syscall/js"
	"time"
)

var kvMap = make(map[string] []byte) // 内存键值对

// 加密结果
type encryptResult struct {
	enc string // 加密密文base64格式
	key string // 加密秘钥base64格式
	err error // 错误信息
}

// 解密结果
type decryptResult struct {
	dec []byte // 解密后字节码
	err error // 错误信息
}

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
func doEncrypt(_ js.Value, data []js.Value) interface{} {
	Promise := js.Global().Get("Promise")
	callback := js.FuncOf(func(_ js.Value, cb []js.Value) interface{} {
		
		Error := js.Global().Get("Error")
		resolve := cb[0]
		reject := cb[1]
		
		// 判断参数是否正确
		if len(data) < 1 {
			reject.Invoke(Error.New("参数不足"))
			return nil
		}
		
		channel := make(chan encryptResult, 1)
		// 对内容进行sm4加密
		go doSm4Encrypt(data[0].String(), channel)
		result := <- channel
		if result.err != nil {
			reject.Invoke(Error.New(result.err))
			return nil
		}
		
 		resolve.Invoke([]interface{}{result.enc, result.key})
		return nil
	})
	return Promise.New(callback)
}

// 暴露给js的解密方法
func doDecrypt(_ js.Value, data []js.Value) interface{} {
	Promise := js.Global().Get("Promise")
	callback := js.FuncOf(func(_ js.Value, cb []js.Value) interface{} {
		
		Error := js.Global().Get("Error")
		resolve := cb[0]
		reject := cb[1]
		
		// 判断参数是否正确
		if len(data) < 2 {
			reject.Invoke(Error.New("参数不足"))
			return nil
		}
		
		channel := make(chan decryptResult, 1)
		// 对内容进行sm4加密
		go doSm4Decrypt(data[0].String(), data[1].String(), channel)
		result := <- channel
		if result.err != nil {
			reject.Invoke(Error.New(result.err))
			return nil
		}
		
		resolve.Invoke(string(result.dec))
		return nil
	})
	return Promise.New(callback)
}

// sm4加密报文
// @param data string 加密字符串
// @param channel chan 通道
// @return encryptResult
func doSm4Encrypt(data string, channel chan encryptResult) {
	result := encryptResult{}
	// 生成随机秘钥
	key := initRandomKey()
	// 通过随机秘钥对内容进行加密
	enc, err := sm4.Sm4Ecb(key, []byte(data), true)
	if err != nil {
		result.err = err
		channel <- result
		return
	}
	encB64 := base64.StdEncoding.EncodeToString(enc)
	
	// 通过sm2加密随机秘钥
	keyB64, err := encryptKey(key)
	if err != nil {
		result.err = err
		channel <- result
		return
	}
	
	// 将密文秘钥与明文秘钥通过map进行存储
	setMap(keyB64, key)
	
	result.enc = encB64
	result.key = keyB64
	channel <- result
	return
}

// sm4解密报文
// @param data 需解密字符串base64编码
// @param key 秘钥密文base64编码
// @return decryptResult
func doSm4Decrypt(data string, key string, channel chan decryptResult) {
	// 创建结果
	result := decryptResult{}
	
	// 密文转byte数组
	dataByte, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		result.err = err
		channel <- result
		return
	}
	
	// 获取明文sm4秘钥
	keyByte, err := getMap(key)
	if err != nil {
		result.err = err
		channel <- result
		return
	}
	
	// 解密
	dec, err := sm4.Sm4Ecb(keyByte, dataByte, false) // 解密
	if err != nil {
		result.err = err
		channel <- result
		return
	}
	
	result.dec = dec
	channel <- result
	return
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
	pub, err := x509.ReadPublicKeyFromHex("041bf86ecf5d8699d2b22d4eb88e7118ed8b129ea2d0f45445ec34e72adfce064b61e98d88e6165612c9c939ffbc3b4789ab47775d72020d80e68109dfef97709f")
	if err != nil {
		return "", err
	}
	enc, err := sm2.Encrypt(pub, key, cRand.Reader, 0) //sm2加密
	if err != nil {
		return "", err
	}
	b64 := base64.StdEncoding.EncodeToString(enc)

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

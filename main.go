package main

import (
	"crypto/rand"
	"fmt"
	"gm/sm2"
	"io/ioutil"
)

func main(){
	testSM2()
}


func testSM2(){
	data, err := ioutil.ReadFile("test.txt")
	//data := []byte{1, 2, 3, 4, 5, 6, 7}
	fmt.Println("read:",string(data))
	priv, pub, err := sm2.GenerateKey(rand.Reader)
	if(err != nil){
		fmt.Println(err)
		return
	}
	fmt.Println("priv:", priv.D)
	fmt.Println("pub.x:", pub.X)
	fmt.Println("pub.y:", pub.Y)
	Cipertext, erro := sm2.Encrypt(pub, data)
	if(erro != nil){
		fmt.Println(err)
		return
	}
	fmt.Println("C1:", Cipertext.C1)
	fmt.Println("C2:", Cipertext.C2)
	fmt.Println("C3:", Cipertext.C3)
	Entext, error := sm2.Decrypt(priv, Cipertext)
	if(error != nil){
		fmt.Println(err)
		return
	}
	fmt.Println("entext:", string(Entext))
}



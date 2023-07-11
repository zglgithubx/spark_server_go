package main

import (
	"fmt"
	"net/http"
	"spark/auth"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

type Info struct {
	privateKey     string
	encipheredData string
}
type Request struct {
	Data string `json:"data"`
}

var (
	keyMap = make(map[string]Info)
)

func main() {
	e := echo.New()
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     []string{"http://localhost:4000"},
		AllowCredentials: true,
		AllowMethods:     []string{echo.GET, echo.HEAD, echo.PUT, echo.PATCH, echo.POST, echo.DELETE, echo.OPTIONS},
	}))
	e.GET("/api/getTicket", genTicket)
	e.POST("/api/getUrl", genUrl)
	e.Logger.Fatal(e.Start(":8081"))
}

func genTicket(ctx echo.Context) error {
	//生成密钥对
	privateKey, publicKey := auth.GenerateRSAKey(1024)
	message := []byte(strconv.Itoa(int(time.Now().UnixMilli())))
	//公钥加密
	cipherText := auth.RSA_Encrypt(message, publicKey)
	info := new(Info)
	info.privateKey = privateKey
	info.encipheredData = string(cipherText)
	res := uuid.New().String()
	keyMap[res] = *info
	return ctx.String(http.StatusOK, res)
}
func genUrl(ctx echo.Context) error {
	request := new(Request)
	ctx.Bind(request)
	fmt.Println(request)
	data := request.Data
	if data == "" {
		return ctx.JSON(http.StatusNoContent, "数据为空")
	}
	info := keyMap[data]
	cipherText := []byte(info.encipheredData)
	privateKey := info.privateKey
	delete(keyMap, ctx.FormValue("data"))
	//私钥解密
	plainText := auth.RSA_Decrypt(cipherText, privateKey)
	start, err := strconv.Atoi(string(plainText))
	if err != nil {
		fmt.Printf("strconv.Atoi failed, err:%v\n", err)
	}
	end := time.Now().UnixMilli()
	if end-int64(start) > 200 {
		return ctx.JSON(http.StatusOK, "timeout")
	}
	hostUrl := "https://spark-api.xf-yun.com/v1.1/chat"
	apiSecret := "MTdlOGUwYWU3N2MzYTE1OThjN2FiMjhl"
	apiKey := "de2518f5fc0af6edd896590c27af739e"
	return ctx.String(http.StatusOK, auth.AuthorizationUrl(hostUrl, apiKey, apiSecret))
}

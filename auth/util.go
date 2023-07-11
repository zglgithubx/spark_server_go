package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"
)

func AuthorizationUrl(hostUrl string, apiKey string, apiSecret string) string {
	URL, err := url.Parse(hostUrl)
	if err != nil {
		fmt.Println("Error parsing URL:", err)
		return ""
	}
	fmt.Println("Url before modification is", URL.Path)
	//Thu, 06 Jul 2023 03:32:19 GMT
	timeStr := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
	fmt.Println("timeStr is", timeStr)
	var builder strings.Builder
	builder.WriteString("host: ")
	builder.WriteString(URL.Host)
	builder.WriteString("\n")
	builder.WriteString("date: ")
	builder.WriteString(timeStr)
	builder.WriteString("\n")
	builder.WriteString("GET ")
	builder.WriteString(URL.Path)
	builder.WriteString(" HTTP/1.1")
	mac := hmac.New(sha256.New, []byte(apiSecret))
	mac.Write([]byte(builder.String()))
	basebefore := mac.Sum([]byte(""))
	signature := base64.StdEncoding.EncodeToString(basebefore)
	authorization_origin := fmt.Sprintf("api_key=\"%s\",algorithm=\"%s\",headers=\"%s\",signature=\"%s\"", apiKey, "hmac-sha256", "host date request-line", signature)
	authorization := base64.StdEncoding.EncodeToString([]byte(authorization_origin))
	httpUrl, err1 := url.Parse("https://" + URL.Host + URL.Path)
	if err1 != nil {
		fmt.Println("Error parsing URL:", err1)
		return ""
	}
	query := httpUrl.Query()
	query.Set("authorization", authorization)
	query.Set("date", timeStr)
	query.Set("host", URL.Host)
	httpUrl.RawQuery = query.Encode()
	fmt.Println("Url after modification is:", httpUrl.String())
	return httpUrl.String()
}

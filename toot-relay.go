package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/payload"
	"github.com/sideshow/apns2/token"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"

	httptrace "gopkg.in/DataDog/dd-trace-go.v1/contrib/net/http"
	dd_logrus "gopkg.in/DataDog/dd-trace-go.v1/contrib/sirupsen/logrus"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

type Message struct {
	isProduction bool
	notification *apns2.Notification
	requestLog   *log.Entry // For logging with datadog context
}

var (
	developmentClient *apns2.Client
	productionClient  *apns2.Client
	topic             string
	messageChan       chan *Message
	maxQueueSize      int
	maxWorkers        int
	ctx               context.Context
)

func worker(workerId int) {
	log.Info(fmt.Sprintf("starting worker %d", workerId))
	defer log.Info(fmt.Sprintf("stopping worker %d", workerId))

	var client *apns2.Client

	for msg := range messageChan {
		if msg.isProduction {
			client = productionClient
		} else {
			client = developmentClient
		}

		res, err := client.Push(msg.notification)

		if err != nil {
			msg.requestLog.Error(fmt.Sprintf("Push error: %s", err))
			continue
		}

		if res.Sent() {
			msg.requestLog.WithFields(log.Fields{
				"status-code":  res.StatusCode,
				"apns-id":      res.ApnsID,
				"reason":       res.Reason,
				"device-token": msg.notification.DeviceToken,
				"expiration":   msg.notification.Expiration,
				"priority":     msg.notification.Priority,
				"collapse-id":  msg.notification.CollapseID,
			}).Info(fmt.Sprintf("Sent notification (%v)", res.StatusCode))
		} else {
			msg.requestLog.WithFields(log.Fields{
				"status-code": res.StatusCode,
				"apns-id":     res.ApnsID,
				"reason":      res.Reason,
			}).Error(fmt.Sprintf("Failed to send notification (%v)", res.StatusCode))
		}
	}
}

func main() {
	tracer.Start()
	defer tracer.Stop()

	mux := httptrace.NewServeMux()

	log.AddHook(&dd_logrus.DDContextLogHook{})

	ctx = context.Background()

	flag.IntVar(&maxQueueSize, "max-queue-size", 4096, "Maximum number of messages to queue")
	flag.IntVar(&maxWorkers, "max-workers", 8, "Maximum number of workers")
	flag.Parse()

	// APNs トークン認証 (.p8) 用の設定。
	// TOPIC は Bundle ID (例: com.zonepane.zero)。デフォルト不要で、未設定なら fatal。
	// AUTH_KEY_FILE は Apple Developer Portal の Keys から発行した .p8 ファイルのパス。
	// KEY_ID は同 Key の 10 文字 ID、TEAM_ID は Apple Developer Team ID (10 文字)。
	topic = env("TOPIC", "")
	if topic == "" {
		log.Fatal("TOPIC env var (Bundle ID, e.g. com.zonepane.zero) must be set")
	}
	authKeyFile := env("AUTH_KEY_FILE", "AuthKey.p8")
	keyID := env("KEY_ID", "")
	teamID := env("TEAM_ID", "")
	if keyID == "" || teamID == "" {
		log.Fatal("KEY_ID and TEAM_ID env vars must be set")
	}

	port := env("PORT", "42069")
	tlsCrtFile := env("CRT_FILENAME", "webpush-apn-relay.crt")
	tlsKeyFile := env("KEY_FILENAME", "webpush-apn-relay.key")
	// CA_FILENAME can be set to a file that contains PEM encoded certificates that will be
	// used as the sole root CAs when connecting to the Apple Notification Service API.
	// If unset, the system-wide certificate store will be used.
	caFile := env("CA_FILENAME", "")
	var rootCAs *x509.CertPool

	if caPEM, err := os.ReadFile(caFile); err == nil {
		rootCAs = x509.NewCertPool()
		if ok := rootCAs.AppendCertsFromPEM(caPEM); !ok {
			log.Fatal(fmt.Sprintf("CA file %s specified but no CA certificates could be loaded\n", caFile))
		}
	}

	// .p8 トークン認証で APNs クライアントを構築 (sandbox/production 両方)。
	// .p12 証明書認証から切り替え: 年次更新不要、IAM 風の鍵管理が可能。
	authKey, err := token.AuthKeyFromFile(authKeyFile)
	if err != nil {
		log.Fatal(fmt.Sprintf("Error loading auth key file %s: %s", authKeyFile, err))
	}
	tk := &token.Token{
		AuthKey: authKey,
		KeyID:   keyID,
		TeamID:  teamID,
	}
	developmentClient = apns2.NewTokenClient(tk).Development()
	productionClient = apns2.NewTokenClient(tk).Production()

	if rootCAs != nil {
		developmentClient.HTTPClient.Transport.(*http2.Transport).TLSClientConfig.RootCAs = rootCAs
		productionClient.HTTPClient.Transport.(*http2.Transport).TLSClientConfig.RootCAs = rootCAs
	}

	mux.HandleFunc("/relay-to/", handler)

	messageChan = make(chan *Message, maxQueueSize)
	for i := 1; i <= maxWorkers; i++ {
		go worker(i)
	}

	if _, err := os.Stat(tlsCrtFile); !os.IsNotExist(err) {
		log.Fatal(http.ListenAndServeTLS(":"+port, tlsCrtFile, tlsKeyFile, mux))
	} else {
		log.Fatal(http.ListenAndServe(":"+port, mux))
	}
}

func handler(writer http.ResponseWriter, request *http.Request) {
	span, sctx := tracer.StartSpanFromContext(ctx, "web.request", tracer.ResourceName(request.RequestURI))
	defer span.Finish()

	requestLog := log.WithContext(sctx)

	components := strings.Split(request.URL.Path, "/")

	if len(components) < 4 {
		writer.WriteHeader(500)
		fmt.Fprintln(writer, "Invalid URL path:", request.URL.Path)
		requestLog.Error(fmt.Sprintf("Invalid URL path: %s", request.URL.Path))
		return
	}

	isProduction := components[2] == "production"

	notification := &apns2.Notification{}
	notification.DeviceToken = components[3]

	buffer := new(bytes.Buffer)
	buffer.ReadFrom(request.Body)
	encodedString := encode85(buffer.Bytes())
	// プレースホルダ alert を常に含める (重要)。
	// iOS の NSE (UNNotificationServiceExtension) は「表示される alert を持つ通知」かつ
	// mutable-content:1 のときだけ起動する。alert が無い (content-available のみの silent push)
	// と NSE が起動せず、端末で復号できない = 通知が一切表示されない。
	// 公式 webpush-apn-relay が Alert("🎺") を入れていたのはこの理由。
	// (Android FCM relay とは逆: FCM は alert があると background/kill で onMessageReceived が
	//  呼ばれないため alert 削除が正解だが、APNs は alert が無いと NSE が起動しないため必須。)
	// NSE が復号後に必ず alert を実 Mastodon 通知本文へ差し替えるため、このプレースホルダは
	// NSE 成功時はユーザーに見えず、NSE 失敗/タイムアウト時のみフォールバックとして表示される。
	placeholderAlert := env("PLACEHOLDER_ALERT", "New notification")
	payload := payload.NewPayload().Alert(placeholderAlert).MutableContent().ContentAvailable().Custom("p", encodedString)

	if len(components) > 4 {
		payload.Custom("x", strings.Join(components[4:], "/"))
	}

	notification.Payload = payload
	notification.Topic = topic
	// iOS 13+ では apns-push-type ヘッダが事実上必須。未指定だと APNs が delivery を
	// 保証しない。Mastodon Web Push は端末で復号して alert 表示する設計なので
	// "alert" タイプを明示する。本実装でも残す改修。
	notification.PushType = apns2.PushTypeAlert

	switch request.Header.Get("Content-Encoding") {
	case "aesgcm":
		if publicKey, err := encodedValue(request.Header, "Crypto-Key", "dh"); err == nil {
			payload.Custom("k", publicKey)
		} else {
			writer.WriteHeader(500)
			fmt.Fprintln(writer, "Error retrieving public key:", err)
			requestLog.Error(fmt.Sprintf("Error retrieving public key: %s", err))
			return
		}

		if salt, err := encodedValue(request.Header, "Encryption", "salt"); err == nil {
			payload.Custom("s", salt)
		} else {
			writer.WriteHeader(500)
			fmt.Fprintln(writer, "Error retrieving salt:", err)
			requestLog.Error(fmt.Sprintf("Error retrieving salt: %s", err))
			return
		}
	case "aes128gcm":
		// Mastodon 4.4+ の標準。Crypto-Key/Encryption ヘッダは含まれず、
		// salt と server public key は body 内に内包される (RFC 8188)。
		// relay 側は body を z85 拡張エンコードして p に詰めるだけで、
		// NSE 側 (CryptoKit) で復号する。
		// クライアント (NSE) が aes128gcm / aesgcm を判別できるよう rfc="1" を付与する。
		// rfc 無し = aesgcm (k/s から復号)、rfc="1" = aes128gcm (salt/serverPubKey は body 内包)。
		// Android FCM relay と整合する設計で、Mastodon 4.4+ の実 push 復号に必須。
		payload.Custom("rfc", "1")
	default:
		writer.WriteHeader(415)
		fmt.Fprintln(writer, "Unsupported Content-Encoding:", request.Header.Get("Content-Encoding"))
		requestLog.Error(fmt.Sprintf("Unsupported Content-Encoding: %s", request.Header.Get("Content-Encoding")))
		return
	}

	if seconds := request.Header.Get("TTL"); seconds != "" {
		if ttl, err := strconv.Atoi(seconds); err == nil {
			notification.Expiration = time.Now().Add(time.Duration(ttl) * time.Second)
		}
	}

	if topic := request.Header.Get("Topic"); topic != "" {
		notification.CollapseID = topic
	}

	switch request.Header.Get("Urgency") {
	case "very-low", "low":
		notification.Priority = apns2.PriorityLow
	default:
		notification.Priority = apns2.PriorityHigh
	}

	messageChan <- &Message{isProduction, notification, requestLog}

	// always reply w/ success, since we don't know how apple responded
	writer.WriteHeader(201)
}

func env(name, defaultValue string) string {
	if value, isPresent := os.LookupEnv(name); isPresent {
		return value
	} else {
		return defaultValue
	}
}

func encodedValue(header http.Header, name, key string) (string, error) {
	keyValues := parseKeyValues(header.Get(name))
	value, exists := keyValues[key]
	if !exists {
		return "", fmt.Errorf("value %s not found in header %s", key, name)
	}

	bytes, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}

	return encode85(bytes), nil
}

func parseKeyValues(values string) map[string]string {
	f := func(c rune) bool {
		return c == ';'
	}

	entries := strings.FieldsFunc(values, f)

	m := make(map[string]string)
	for _, entry := range entries {
		parts := strings.Split(entry, "=")
		m[parts[0]] = parts[1]
	}

	return m
}

var z85digits = []byte("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#")

func encode85(bytes []byte) string {
	numBlocks := len(bytes) / 4
	suffixLength := len(bytes) % 4

	encodedLength := numBlocks * 5
	if suffixLength != 0 {
		encodedLength += suffixLength + 1
	}

	encodedBytes := make([]byte, encodedLength)

	src := bytes
	dest := encodedBytes
	for block := 0; block < numBlocks; block++ {
		value := binary.BigEndian.Uint32(src)

		for i := 0; i < 5; i++ {
			dest[4-i] = z85digits[value%85]
			value /= 85
		}

		src = src[4:]
		dest = dest[5:]
	}

	if suffixLength != 0 {
		value := 0

		for i := 0; i < suffixLength; i++ {
			value *= 256
			value |= int(src[i])
		}

		for i := 0; i < suffixLength+1; i++ {
			dest[suffixLength-i] = z85digits[value%85]
			value /= 85
		}
	}

	return string(encodedBytes)
}

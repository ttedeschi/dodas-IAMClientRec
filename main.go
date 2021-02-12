package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"

	"github.com/dciangot/sts-wire/pkg/core"
)

func main() {
	inputReader := *bufio.NewReader(os.Stdin)
	scanner := core.GetInputWrapper{
		Scanner: inputReader,
	}

	instance := ""
	if len(os.Args) > 1 {
		instance = os.Args[1]
		if instance == "-h" {
			fmt.Println("dodas-IAMClientRec <client name>")
			return
		} else if instance == "" {
			instance = "automatic"
		}
	} else {
		instance = "automatic"
	}

	iamServer := ""

	iamServer = os.Getenv("IAM_INSTANCE")

	if iamServer == "" {
		if len(os.Args) > 2 {
			iamServer = os.Args[2]
		}
	}
	if iamServer == "" {
		fmt.Println("No IAM instance specified, please set env IAM_INSTANCE or use:")
		fmt.Println("dodas-IAMClientRec <client name> <IAM instance>")
		return
	}

	callback := os.Getenv("OAUTH_CALLBACK")

	if callback == "" {
		fmt.Println("No Service redirect callback url specified, please set env OAUTH_CALLBACK")
		return
	}

	confDir := "." + instance

	_, err := os.Stat(confDir)
	if os.IsNotExist(err) {
		os.Mkdir(confDir, os.ModePerm)
	}

	clientConfig := core.IAMClientConfig{
		CallbackURL: callback,
		ClientName:  instance,
	}

	// Create a CA certificate pool and add cert.pem to it
	//caCert, err := ioutil.ReadFile("MINIO.pem")
	//if err != nil {
	//	log.Fatal(err)
	//}
	//caCertPool := x509.NewCertPool()
	//caCertPool.AppendCertsFromPEM(caCert)

	// Create the TLS Config with the CA pool and enable Client certificate validation
	cfg := &tls.Config{
		//ClientCAs: caCertPool,
		InsecureSkipVerify: true,
	}
	//cfg.BuildNameToCertificate()

	tr := &http.Transport{
		TLSClientConfig: cfg,
	}

	httpClient := &http.Client{
		Transport: tr,
	}

	clientIAM := core.InitClientConfig{
		ConfDir:        confDir,
		ClientConfig:   clientConfig,
		Scanner:        scanner,
		HTTPClient:     *httpClient,
		IAMServer:      iamServer,
		ClientTemplate: ClientTemplate,
		NoPWD:          true,
	}

	_, clientResponse, _, err := clientIAM.InitClient(instance)
	if err != nil {
		panic(err)
	}

	fmt.Println(clientResponse.ClientID)
	fmt.Println(clientResponse.ClientSecret)
}

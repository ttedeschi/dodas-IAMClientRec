package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/template"

	"github.com/awnumar/memguard"
	"github.com/denisbrodbeck/machineid"
	"github.com/gookit/color"
	"github.com/rs/zerolog/log"
)

func tryContainerMachineID() (machineID string, err error) {
	// Ref: https://stackoverflow.com/questions/23513045/how-to-check-if-a-process-is-running-inside-docker-container
	cgroupFile, err := os.Open("/proc/self/cgroup")
	if err != nil {
		return machineID, fmt.Errorf("cannot open cgroup: %w", err)
	}

	defer cgroupFile.Close()

	var buff bytes.Buffer

	_, err = buff.ReadFrom(cgroupFile)
	if err != nil {
		return machineID, fmt.Errorf("cannot read cgroup: %w", err)
	}

	for _, line := range strings.Split(buff.String(), "\n") {
		if strings.Contains(line, "/docker/") {
			parts := strings.Split(line, "/docker/")
			if len(parts) != 2 {
				return machineID, fmt.Errorf("not a valid docker container id: %w", err)
			}

			machineID = parts[1]

			break
		}
	}

	if machineID == "" {
		return machineID, fmt.Errorf("docker container id not found: %w", err)
	}

	return machineID, nil
}

func CreateHash(key string) string {
	log.Debug().Msg("create hash")

	id, errID := machineid.ProtectedID("sts-wire")
	if errID != nil {
		if strings.Contains(errID.Error(), "open /etc/machine-id: no such file or directory") {
			// TODO: get a unique uuid for containers:
			// Ref: https://github.com/denisbrodbeck/machineid/issues/5
			// Ref: https://github.com/panta/machineid/blob/master/id_linux.go
			id, errID = tryContainerMachineID()
			if errID != nil {
				id = "notAMachine"
				log.Debug().Str("machineID", id).Msg("Cannot find a docker container id")
			} else {
				log.Debug().Str("machineID", id).Msg("Found docker container id")
			}
		} else {
			panic(errID)
		}
	}

	hasher := hmac.New(md5.New, []byte(id))
	_, errWrite := hasher.Write([]byte(key))

	if errWrite != nil {
		panic(errWrite)
	}

	return hex.EncodeToString(hasher.Sum(nil))
}

func Encrypt(data []byte, password *memguard.Enclave) []byte {
	log.Debug().Msg("encryption - open enclave")

	passphrase, errOpenEnclave := password.Open()
	if errOpenEnclave != nil {
		memguard.SafePanic(errOpenEnclave)
	}

	defer passphrase.Destroy() // Destroy the copy when we return

	log.Debug().Msg("encryption - create cipher")

	block, errNewCiper := aes.NewCipher([]byte(CreateHash(string(passphrase.Bytes()))))
	if errNewCiper != nil {
		panic(errNewCiper)
	}

	log.Debug().Msg("encryption - create block")

	gcm, errNewGCM := cipher.NewGCM(block)
	if errNewGCM != nil {
		panic(errNewGCM.Error())
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	log.Debug().Msg("encryption - encode")

	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	return ciphertext
}

func Decrypt(data []byte, password *memguard.Enclave) []byte {
	log.Debug().Msg("decryption - open enclave")

	passphrase, errOpenEnclave := password.Open()
	if errOpenEnclave != nil {
		memguard.SafePanic(errOpenEnclave)
	}

	defer passphrase.Destroy() // Destroy the copy when we return

	log.Debug().Msg("decryption - create key")

	key := []byte(CreateHash(string(passphrase.Bytes())))

	log.Debug().Msg("decryption - create cipher")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	log.Debug().Msg("decryption - create block")

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	log.Debug().Msg("decryption - decode")

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return plaintext
}

type IAMClientConfig struct {
	CallbackURL string
	Host        string
	Port        int
	ClientName  string
}

type ClientResponse struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Endpoint     string `json:"registration_client_uri"`
}

type InitClientConfig struct {
	ConfDir        string
	ClientConfig   IAMClientConfig
	Scanner        GetInputWrapper
	HTTPClient     http.Client
	IAMServer      string
	ClientTemplate string
	NoPWD          bool
}

func (t *InitClientConfig) InitClient(instance string) (endpoint string, clientResponse ClientResponse, passwd *memguard.Enclave, err error) { //nolint:funlen,gocognit,lll
	filename := t.ConfDir + "/" + instance + ".json"

	log.Debug().Str("filename", filename).Msg("credentials - init client")

	confFile, err := os.Open(filename)

	switch {
	case err != nil && err.Error() != "no such file or directory":
		tmpl, errParser := template.New("client").Parse(t.ClientTemplate)
		if errParser != nil {
			panic(errParser)
		}

		var b bytes.Buffer
		errExecute := tmpl.Execute(&b, t.ClientConfig)

		if errExecute != nil {
			panic(errExecute)
		}

		request := b.String()

		log.Debug().Str("URL", request).Msg("credentials")

		contentType := "application/json"

		log.Debug().Str("REFRESH_TOKEN", os.Getenv("REFRESH_TOKEN")).Msg("credentials")

		if t.IAMServer == "" {
			endpoint, err = t.Scanner.GetInputString("Insert the IAM endpoint",
				"https://iam-demo.cloud.cnaf.infn.it")
			if err != nil {
				panic(err)
			}
		} else if t.IAMServer != "" {
			log.Debug().Str("IAM endpoint used", t.IAMServer).Msg("credentials")
			color.Green.Printf("==> IAM endpoint used: %s\n", t.IAMServer)
			endpoint = t.IAMServer
		}

		register := endpoint + "/register"

		log.Debug().Str("IAM register url", register).Msg("credentials")
		color.Green.Printf("==> IAM register url: %s\n", register)

		resp, err := t.HTTPClient.Post(register, contentType, strings.NewReader(request))
		if err != nil {
			panic(err)
		}

		defer resp.Body.Close()

		log.Debug().Int("StatusCode", resp.StatusCode).Str("Status", resp.Status).Msg("credentials")

		var rbody bytes.Buffer

		_, err = rbody.ReadFrom(resp.Body)
		if err != nil {
			log.Err(err).Msg("credentials - read body")
			panic(err)
		}

		log.Debug().Str("body", rbody.String()).Msg("credentials")

		errUnmarshall := json.Unmarshal(rbody.Bytes(), &clientResponse)
		if errUnmarshall != nil {
			panic(errUnmarshall)
		}

		clientResponse.Endpoint = endpoint

		if !t.NoPWD { //nolint:nestif
			var errGetPasswd error

			// TODO: verify branch when REFRESH_TOKEN is passed and is not empty string
			if os.Getenv("REFRESH_TOKEN") == "" {
				passMsg := fmt.Sprintf("%s Insert a pasword for the secret's encryption: ", color.Yellow.Sprint("==>"))
				passwd, errGetPasswd = t.Scanner.GetPassword(passMsg, false)

				if errGetPasswd != nil {
					panic(errGetPasswd)
				}
			} else {
				passwd = memguard.NewEnclave([]byte("nopassword"))
			}

			dumpClient := Encrypt(rbody.Bytes(), passwd)

			filename := t.ConfDir + "/" + instance + ".json"

			curFile, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
			if err != nil {
				log.Err(err).Msg("credentials - dump client")

				panic(err)
			}

			_, err = curFile.Write(dumpClient)
			if err != nil {
				log.Err(err).Msg("credentials - dump client")

				panic(err)
			}

			err = curFile.Close()
			if err != nil {
				log.Err(err).Msg("credentials - dump client")

				panic(err)
			}
		}
	case err == nil && !t.NoPWD:
		var errGetPasswd error
		defer confFile.Close()

		var rbody bytes.Buffer

		_, err = rbody.ReadFrom(confFile)
		if err != nil {
			log.Err(err).Msg("credentials - init client")
			panic(err)
		}

		// TODO: verify branch when REFRESH_TOKEN is passed and is not empty string
		if os.Getenv("REFRESH_TOKEN") == "" {
			passMsg := fmt.Sprintf("%s Insert a pasword for the secret's decryption: ", color.Yellow.Sprint("==>"))
			passwd, errGetPasswd = t.Scanner.GetPassword(passMsg, true)

			if errGetPasswd != nil {
				panic(errGetPasswd)
			}
		} else {
			passwd = memguard.NewEnclave([]byte("nopassword"))
		}

		errUnmarshal := json.Unmarshal(Decrypt(rbody.Bytes(), passwd), &clientResponse)
		if errUnmarshal != nil {
			panic(errUnmarshal)
		}

		log.Debug().Str("response endpoint", clientResponse.Endpoint).Msg("credentials")
		endpoint = strings.Split(clientResponse.Endpoint, "/register")[0]
	default:
		log.Err(err).Msg("credentials - init client")
		panic(err)
	}

	if endpoint == "" {
		panic("Something went wrong. No endpoint selected")
	}

	return endpoint, clientResponse, passwd, nil
}

type GetInputWrapper struct {
	Scanner bufio.Reader
}

func (t *GetInputWrapper) GetInputString(question string, def string) (text string, err error) {
	if def != "" {
		fmt.Printf("%s %s (press enter for default [%s]):", color.Yellow.Sprint("|=>"), question, def)
		text, err = t.Scanner.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("GetInputString %w", err)
		}

		text = strings.ReplaceAll(text, "\r\n", "")
		text = strings.ReplaceAll(text, "\n", "")

		if text == "" {
			text = def
		}
	} else {
		fmt.Printf("|=> %s:", question)
		text, err = t.Scanner.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("GetInputString %w", err)
		}
		text = strings.ReplaceAll(text, "\n", "")
	}

	return text, nil
}

func main() {
	inputReader := *bufio.NewReader(os.Stdin)
	scanner := GetInputWrapper{
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

	clientConfig := IAMClientConfig{
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

	clientIAM := InitClientConfig{
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

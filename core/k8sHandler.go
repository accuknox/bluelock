package core

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/daemon1024/bluelock/common"
	"github.com/kubearmor/KubeArmor/KubeArmor/log"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	kspclient "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/client/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
)

type K8sHandler struct {
	K8sClient   *kubernetes.Clientset
	KSPClient   *kspclient.Clientset
	HTTPClient  *http.Client
	WatchClient *http.Client

	K8sToken string
	K8sHost  string
	K8sPort  string
}

var K8s *K8sHandler

func init() {
	K8s = NewK8sHandler()
}

// NewK8sHandler Function
func NewK8sHandler() *K8sHandler {
	kh := &K8sHandler{}

	if val, ok := os.LookupEnv("KUBERNETES_SERVICE_HOST"); ok {
		kh.K8sHost = val
	} else {
		kh.K8sHost = "127.0.0.1"
	}

	if val, ok := os.LookupEnv("KUBERNETES_PORT_443_TCP_PORT"); ok {
		kh.K8sPort = val
	} else {
		kh.K8sPort = "8001" // kube-proxy
	}

	kh.HTTPClient = &http.Client{
		Timeout: time.Second * 5,
		// #nosec
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	kh.WatchClient = &http.Client{
		// #nosec
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	config, err := ctrl.GetConfig()
	if err != nil {
		log.Warnf("Error creating kubernetes config, %s", err)
		return kh
	}

	kh.KSPClient, err = kspclient.NewForConfig(config)
	if err != nil {
		log.Warnf("Error creating ksp clientset, %s", err)
		return kh
	}

	return kh
}

// ================ //
// == K8s Client == //
// ================ //

// InitK8sClient Function
func (kh *K8sHandler) InitK8sClient() bool {
	if !common.IsK8sEnv() { // not Kubernetes
		return false
	}

	if kh.K8sClient == nil {
		if common.IsInK8sCluster() {
			return kh.InitInclusterAPIClient()
		}
		if common.IsK8sLocal() {
			return kh.InitLocalAPIClient()
		}
		return false
	}

	return true
}

// InitLocalAPIClient Function
func (kh *K8sHandler) InitLocalAPIClient() bool {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = os.Getenv("HOME") + "/.kube/config"
		if _, err := os.Stat(filepath.Clean(kubeconfig)); err != nil {
			return false
		}
	}

	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return false
	}

	// creates the clientset
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return false
	}
	kh.K8sClient = client

	return true
}

// InitInclusterAPIClient Function
func (kh *K8sHandler) InitInclusterAPIClient() bool {
	read, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return false
	}
	kh.K8sToken = string(read)

	// create the configuration by token
	kubeConfig := &rest.Config{
		Host:        "https://" + kh.K8sHost + ":" + kh.K8sPort,
		BearerToken: kh.K8sToken,
		// #nosec
		TLSClientConfig: rest.TLSClientConfig{
			Insecure: true,
		},
	}

	client, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return false
	}
	kh.K8sClient = client

	return true
}

// ============== //
// == API Call == //
// ============== //

// DoRequest Function
func (kh *K8sHandler) DoRequest(cmd string, data interface{}, path string) ([]byte, error) {
	URL := ""

	if common.IsInK8sCluster() {
		URL = "https://" + kh.K8sHost + ":" + kh.K8sPort
	} else {
		URL = "http://" + kh.K8sHost + ":" + kh.K8sPort
	}

	pbytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(cmd, URL+path, bytes.NewBuffer(pbytes))
	if err != nil {
		return nil, err
	}

	if common.IsInK8sCluster() {
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", kh.K8sToken))
	}

	resp, err := kh.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	resBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if err := resp.Body.Close(); err != nil {
		kg.Err(err.Error())
	}

	return resBody, nil
}

// ====================== //
// == Custom Resources == //
// ====================== //

// CheckCustomResourceDefinition Function
func (kh *K8sHandler) CheckCustomResourceDefinition(resourceName string) bool {
	if !common.IsK8sEnv() { // not Kubernetes
		return false
	}

	exist := false
	apiGroup := metav1.APIGroup{}

	// check APIGroup
	if resBody, errOut := kh.DoRequest("GET", nil, "/apis"); errOut == nil {
		res := metav1.APIGroupList{}
		if errIn := json.Unmarshal(resBody, &res); errIn == nil {
			for _, group := range res.Groups {
				if group.Name == "security.kubearmor.com" {
					exist = true
					apiGroup = group
					break
				}
			}
		}
	}

	// check APIResource
	if exist {
		if resBody, errOut := kh.DoRequest("GET", nil, "/apis/"+apiGroup.PreferredVersion.GroupVersion); errOut == nil {
			res := metav1.APIResourceList{}
			if errIn := json.Unmarshal(resBody, &res); errIn == nil {
				for _, resource := range res.APIResources {
					if resource.Name == resourceName {
						return true
					}
				}
			}
		}
	}

	return false
}

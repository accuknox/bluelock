# EKS Fargate Setup with Accuknox SaaS

1. Create a fargate cluster using eksctl

```
eksctl create cluster --name kubearmor-fargate --region us-east-2 --fargate --nodes 1 --nodes-max 1 --instance-selector-memory 4 --ins
tance-selector-vcpus 2
```

2. Add fargate profile for accuknox-agents

```
eksctl create fargateprofile --namespace accuknox-agents --cluster kubearmor-fargate
```

3. Deploy KubeArmor relay server

```
kubectl apply -f https://raw.githubusercontent.com/daemon1024/bluelock/master/relay-deployment.yaml
```
4. Deploy BlueLock + Demo App

```
kubectl apply -f https://raw.githubusercontent.com/daemon1024/bluelock/master/deployment.yaml
```
5. Onboard Cluster to Accuknox Saas
5.5 Modify Agents Operator ConfigMap to update formula to n/30 to prevent scaling up of resources

6. Try out app
    1. Port-forward App
    ```
     kubectl port-forward pods/armored-application-<pod-hash> 1337:1337
    ```
    2. Connect to the app
    ```
    socat - TCP:localhost:1337
    ```
7. Playaround in the dashboard, apply policies and violate it
    1. Sample Service Account Token Lenient Whitelist Policy
    ```
    https://github.com/daemon1024/bluelock/blob/master/test/bluelock-sa-policy.yaml
    ```
    Apply using SaaS
    2. Try out in socat terminal
    ```
    # cat /run/secrets/kubernetes.io/serviceaccount/token
    # cat /etc/passwd
    # head /run/secrets/kubernetes.io/serviceaccount/token [Permission Denied]
    # head /etc/passwd
    ```
    3. Policy Violation Alerts in SaaS
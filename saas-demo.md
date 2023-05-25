# Deployment Modification to add runtime protection to your workload

The parent binary responsible for runtime security is portable. We need to mount it to the container have it spawn the entrypoint.

We can do this copying to a empty volume using init container and then modify the entrypoint of your app.

We also need to provide it with a Service Account token for it to access Cluster Resources.

Original Deployment:
```yaml
      ...
      containers:
        - name: container
          image: daemon1024/ka-socat-demo
          imagePullPolicy: Always
          ports:
            - containerPort: 1337
      ...
```

Modified Deployment:
```yaml
      ...
      serviceAccountName: kubearmor
      volumes:
        - emptyDir: {}
          name: kubearmor-dir
      initContainers:
        - name: bluelock
          image: daemon1024/bluelock
          imagePullPolicy: Always
          volumeMounts:
            - mountPath: /kubearmor
              name: kubearmor-dir
      containers:
        - name: armored-container
          image: daemon1024/ka-socat-demo
          imagePullPolicy: Always
          command: ["/kubearmor/bluelock","socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:bash,pty,stderr,setsid,sigint,sane"] ## Binary Accepts Container Commands as Argument
          ports:
            - containerPort: 1337
          volumeMounts:
            - mountPath: /kubearmor
              name: kubearmor-dir
          env:
          - name: "SIDEKICK_URL"
            value: "http://kubearmor.kube-system.svc.cluster.local:2801"
      ...
```

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

    -  Modify Agents Operator ConfigMap to update formula to n/30 to prevent scaling up of resources [Hack needed since concept of nodes is different on fargate and it's not compatible with Agents Operator]

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
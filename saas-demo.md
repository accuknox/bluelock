# Why Fargate and challenges assosciated

- Security: Each Pod that runs on Fargate has its own isolation boundary. They don't share the underlying kernel, CPU resources, memory resources, or elastic network interface with another Pod.

- Scalable and Performant: We no longer have to provision, configure, or scale clusters of virtual machines to run containers. Each Pod is it's own VM. This removes the need to choose server types, decide when to scale your clusters, or optimize cluster packing

### Challenges

- No Daemonsets [Existing Deployment Mode Unsupported]
- No Kernel Primitives Allowed or privileges to trace and enforce 

# Reference Diagram

- Existing HLD

![](https://hackmd.io/_uploads/H1bh736Sh.png)

- Updated Design

![](https://hackmd.io/_uploads/rJ4NN3aH2.png)

- Internal Design
![](https://hackmd.io/_uploads/S12tfh6rn.png)



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
    ![](https://hackmd.io/_uploads/r1CXZ2Tr2.png)

    
    2. Try out in socat terminal
    ```
    # cat /run/secrets/kubernetes.io/serviceaccount/token
    # cat /etc/passwd
    # head /run/secrets/kubernetes.io/serviceaccount/token [Permission Denied]
    # head /etc/passwd
    ```
    
    3. Policy Violation Alerts

        - kArmor JSON
        ```json
        {"Timestamp":1685073936,"UpdatedTime":"2023-05-26T04:05:36.097519Z","HostName":"armored-application-77fb54dc69-g4cgh","NamespaceName":"default","PodName":"armored-application-77fb54dc69-g4cgh","Labels":"eks.amazonaws.com/fargate-profile=fp-default,kubearmor.io/container.name=armored-container","ContainerID":"938e0b4bbdbc5c7f8cc1acb319ef59784d495e44b6f66fa41bd0c9180a52986e","ContainerName":"armored-container","ContainerImage":"docker.io/daemon1024/ka-socat-demo:latest@sha256:f6208198172cc4ed73e7f813a982b30221c5c8bb3bf587af16840055ac517fdd","PPID":31,"PID":34,"ParentProcessName":"/usr/bin/bash","ProcessName":"/usr/bin/head","PolicyName":"ksp-armored-lenient-allow-sa","Severity":"7","Tags":"NIST","ATags":["NIST"],"Message":"sa token malicious accessed ","Type":"MatchedPolicy","Source":"/usr/bin/head","Operation":"File","Resource":"/run/secrets/kubernetes.io/serviceaccount/token","Data":"syscall=openat fd=4294967196 flags=0 mode=0","Enforcer":"Ptrace enforcer","Action":"Block","Result":"Permission denied"}
        ```
        - SaaS Alert
        ![](https://hackmd.io/_uploads/H1qTxhTr2.png)

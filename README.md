# Bluelock

**User-space Runtime Security Enforcement for Serverless Containers**

Bluelock is a security engine created by AccuKnox to bring runtime protection to heavily restricted serverless environments like AWS Fargate. 

In environments where you cannot access the host node, load kernel modules, or deploy eBPF probes, Bluelock relies entirely on user-space instrumentation via `ptrace` and `seccomp` to enforce zero-trust security policies.

---

## 🎯 The Problem: Security in Serverless Kubernetes
Standard runtime security tools (like the KubeArmor DaemonSet) operate at the host kernel level. They use eBPF and Linux Security Modules (LSMs like AppArmor, SELinux, BPF-LSM) to monitor and block malicious syscalls across all containers on a node.

**AWS Fargate abstracts the host away.** 
You cannot run privileged DaemonSets, you cannot inject eBPF hooks, and you cannot configure AppArmor profiles. This leaves a gap in runtime enforcement: if an attacker exploits a vulnerability in your Fargate workload (e.g., Log4Shell) and attempts to spawn a reverse shell or read `/etc/shadow`, traditional security tools cannot stop them.

## 💡 The Solution: Process Wrapping with Bluelock
Bluelock solves this by bringing the enforcement mechanism *inside* the container namespace. Instead of monitoring the application from the host kernel, Bluelock hijacks the container's entrypoint, becomes the parent process, and traps the application in a restrictive syscall sandbox.

### How it Works (`ptrace` + `seccomp`)

1. **The Entrypoint Hijack:** Bluelock is injected into your workload (usually via an Init Container and a shared volume). The container's `ENTRYPOINT` is overridden so that `bluelock` boots first.
2. **The Seccomp Speedbump:** Bluelock receives your security policies and then it then applies a BPF `seccomp` filter to itself using. 
3. **The `fork()` and `execve()`:** Bluelock forks and launches your actual application (e.g., `nginx` or `node app.js`) as its direct child. Due to Linux inheritance rules, the child inherits the strict seccomp filter.
4. **The `ptrace` Trap:** Whenever the application executes a sensitive system call, the seccomp filter pauses the application and hands control back to Bluelock.
5. **Enforcement:** Bluelock inspects the syscall arguments. If the action violates your policy, Bluelock returns a `-EACCES` (Permission Denied) error to the application.

---

## 🚀 Deployment

To deploy Bluelock, you must inject the compiled `bluelock` binary into your application container's filesystem and override the container's execution command. See [ECS](./docs/ecs.md) and [EKS](./docs/saas-demo-eks.md) deployment guides for more information.

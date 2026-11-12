{{/*
Shared control-plane API process Deployment.

The API and the optional scan/ingest worker run the same image, arguments,
Postgres identities, secrets, service account and security contract; only the
role, replica count, scheduling and resources differ. Rendering both from one
definition keeps the two pods from drifting.

Call with (dict "root" $ "component" "api"|"worker").
*/}}
{{- define "agent-bom.controlPlaneApiValidate" -}}
{{- $cp := .Values.controlPlane -}}
{{- $postgresSecrets := $cp.postgresSecrets -}}
{{- $worker := $cp.worker | default dict -}}
{{- $autoCorrelationMaxAge := int $cp.autoCorrelation.maxAgeHours -}}
{{- if or (lt $autoCorrelationMaxAge 1) (gt $autoCorrelationMaxAge 8760) -}}
{{- fail "controlPlane.autoCorrelation.maxAgeHours must be between 1 and 8760" -}}
{{- end -}}
{{- $trustedProxy := $cp.api.trustedProxy | default dict -}}
{{- $proxyEnvSet := dict -}}
{{- range $entry := $cp.api.env -}}
{{- if has (get $entry "name") (list "AGENT_BOM_TRUSTED_PROXY_HOPS" "AGENT_BOM_TRUSTED_PROXY_CIDRS") -}}
{{- $_ := set $proxyEnvSet (get $entry "name") true -}}
{{- end -}}
{{- end -}}
{{- $proxyConfigured := or (and $trustedProxy.hops $trustedProxy.cidrs) (eq (len $proxyEnvSet) 2) $trustedProxy.fromSecret -}}
{{- if and $cp.ingress.enabled (not $proxyConfigured) (not $trustedProxy.sharedSourceAccepted) -}}
{{- fail "controlPlane.ingress.enabled requires controlPlane.api.trustedProxy.hops and .cidrs: without them every client behind the ingress shares one authentication failure budget and about ten bad logins refuse everyone. Set them, set controlPlane.api.trustedProxy.fromSecret=true if a Secret in envFrom supplies both variables, or set controlPlane.api.trustedProxy.sharedSourceAccepted=true to accept one shared budget." -}}
{{- end -}}
{{- if and $trustedProxy.fromSecret (not $trustedProxy.secretName) -}}
{{- fail "controlPlane.api.trustedProxy.fromSecret requires controlPlane.api.trustedProxy.secretName, the Secret holding AGENT_BOM_TRUSTED_PROXY_HOPS and AGENT_BOM_TRUSTED_PROXY_CIDRS" -}}
{{- end -}}
{{- $roleEnv := list "AGENT_BOM_API_ROLE" "AGENT_BOM_DISTRIBUTED_SCANS" -}}
{{- range $entry := $cp.api.env -}}
{{- if eq (get $entry "name") "AGENT_BOM_CONTROL_PLANE_REPLICAS" -}}
{{- fail "controlPlane.api.env cannot override AGENT_BOM_CONTROL_PLANE_REPLICAS; use replicas and autoscaling settings" -}}
{{- end -}}
{{- if has (get $entry "name") (list "AGENT_BOM_GRAPH_AUTO_CORRELATE" "AGENT_BOM_GRAPH_AUTO_CORRELATE_MAX_AGE_HOURS") -}}
{{- fail "controlPlane.api.env cannot override automatic correlation variables; use controlPlane.autoCorrelation" -}}
{{- end -}}
{{- if and $worker.enabled (has (get $entry "name") $roleEnv) -}}
{{- fail (printf "controlPlane.api.env cannot set %s when controlPlane.worker.enabled=true; the chart assigns process roles" (get $entry "name")) -}}
{{- end -}}
{{- end -}}
{{- if $worker.enabled -}}
{{- if not $postgresSecrets.enabled -}}
{{- fail "controlPlane.worker.enabled requires controlPlane.postgresSecrets.enabled=true: workers drain the shared Postgres scan_dispatch_queue" -}}
{{- end -}}
{{- range $entry := $worker.extraEnv -}}
{{- if has (get $entry "name") (concat $roleEnv (list "AGENT_BOM_CONTROL_PLANE_REPLICAS" "AGENT_BOM_GRAPH_AUTO_CORRELATE" "AGENT_BOM_GRAPH_AUTO_CORRELATE_MAX_AGE_HOURS" "AGENT_BOM_POSTGRES_URL" "AGENT_BOM_POSTGRES_MAINTENANCE_URL" "AGENT_BOM_POSTGRES_PROVIDER" "ALEMBIC_DATABASE_URL")) -}}
{{- fail (printf "controlPlane.worker.extraEnv cannot set %s; it is chart-managed" (get $entry "name")) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if $postgresSecrets.enabled -}}
{{- $appSecret := required "controlPlane.postgresSecrets.appSecretRef.name is required" $postgresSecrets.appSecretRef.name -}}
{{- $maintenanceSecret := required "controlPlane.postgresSecrets.maintenanceSecretRef.name is required" $postgresSecrets.maintenanceSecretRef.name -}}
{{- $adminSecret := required "controlPlane.postgresSecrets.adminSecretRef.name is required" $postgresSecrets.adminSecretRef.name -}}
{{- if ne (len (uniq (list $appSecret $maintenanceSecret $adminSecret))) 3 -}}
{{- fail "controlPlane.postgresSecrets app, maintenance, and admin Secret names must be distinct" -}}
{{- end -}}
{{- range $entry := $cp.api.env -}}
{{- if has (get $entry "name") (list "AGENT_BOM_POSTGRES_URL" "AGENT_BOM_POSTGRES_MAINTENANCE_URL" "AGENT_BOM_POSTGRES_PROVIDER" "ALEMBIC_DATABASE_URL") -}}
{{- fail "controlPlane.api.env cannot override canonical Postgres identity variables when controlPlane.postgresSecrets.enabled=true" -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- include "agent-bom.controlPlaneShutdownValidate" . -}}
{{- $pool := $cp.postgres.pool -}}
{{- if or (lt (int $pool.minSize) 1) (lt (int $pool.maxSize) (int $pool.minSize)) -}}
{{- fail "controlPlane.postgres.pool.minSize must be at least 1 and no larger than controlPlane.postgres.pool.maxSize" -}}
{{- end -}}
{{- $_ := include "agent-bom.postgresConnectionLimits" . -}}
{{- range $entry := concat $cp.api.env ($worker.extraEnv | default list) -}}
{{- if has (get $entry "name") (list "AGENT_BOM_POSTGRES_POOL_MIN_SIZE" "AGENT_BOM_POSTGRES_POOL_MAX_SIZE") -}}
{{- fail (printf "%s is chart-managed: set controlPlane.postgres.pool.minSize and .maxSize, which also size the Postgres role connection limits" (get $entry "name")) -}}
{{- end -}}
{{- if has (get $entry "name") (list "AGENT_BOM_SHUTDOWN_DRAIN_SECONDS" "AGENT_BOM_GRACEFUL_SHUTDOWN_SECONDS") -}}
{{- fail (printf "%s is chart-managed: set controlPlane.api.shutdown, which is checked against terminationGracePeriodSeconds" (get $entry "name")) -}}
{{- end -}}
{{- end -}}
{{- include "agent-bom.controlPlaneListenerAttestationValidate" . -}}
{{- end }}

{{/*
Every API-image process sharing the control-plane database: API capacity plus
worker capacity when the worker split is on. Feeds the shared-state guards.
*/}}
{{- define "agent-bom.controlPlaneProcessCapacity" -}}
{{- $capacity := int (include "agent-bom.controlPlaneReplicaCapacity" .Values.controlPlane.api) -}}
{{- $worker := .Values.controlPlane.worker | default dict -}}
{{- if $worker.enabled -}}
{{- $capacity = add $capacity (int (include "agent-bom.controlPlaneReplicaCapacity" $worker)) -}}
{{- end -}}
{{- $capacity -}}
{{- end -}}

{{/*
Termination budget: pre-stop sleep (API only), in-flight request wait and
background drain, plus a 5 s margin, must fit each pod's grace period.
*/}}
{{- define "agent-bom.controlPlaneShutdownValidate" -}}
{{- $cp := .Values.controlPlane -}}
{{- $shutdown := $cp.api.shutdown -}}
{{- $work := add (int $shutdown.gracefulShutdownSeconds) (int $shutdown.drainSeconds) 5 -}}
{{- $apiBudget := add $work (int $shutdown.preStopSleepSeconds) -}}
{{- $apiGrace := int $cp.api.terminationGracePeriodSeconds -}}
{{- if and $cp.api.enabled (lt $apiGrace $apiBudget) -}}
{{- fail (printf "controlPlane.api.terminationGracePeriodSeconds=%d is shorter than controlPlane.api.shutdown needs (preStopSleepSeconds + gracefulShutdownSeconds + drainSeconds + 5 = %d); Kubernetes would kill the pod mid-drain" $apiGrace $apiBudget) -}}
{{- end -}}
{{- $worker := $cp.worker | default dict -}}
{{- $workerGrace := int ($worker.terminationGracePeriodSeconds | default $apiGrace) -}}
{{- if and $worker.enabled (lt $workerGrace $work) -}}
{{- fail (printf "controlPlane.worker.terminationGracePeriodSeconds=%d is shorter than controlPlane.api.shutdown needs (gracefulShutdownSeconds + drainSeconds + 5 = %d)" $workerGrace $work) -}}
{{- end -}}
{{- end -}}

{{/*
A clustered or production API listening beyond loopback refuses to start
without trusted-proxy attestation or app-native mTLS
(agent_bom.api.auth_posture.require_safe_control_plane_listener). Refuse to
render the crash loop instead.
*/}}
{{- define "agent-bom.controlPlaneListenerAttestationValidate" -}}
{{- $api := .Values.controlPlane.api -}}
{{- $attestation := $api.listenerAttestation | default dict -}}
{{- $env := dict -}}
{{- range $entry := $api.env -}}
{{- $_ := set $env (get $entry "name") (toString (get $entry "value" | default "<from>")) -}}
{{- end -}}
{{- $truthy := list "1" "true" "yes" "on" -}}
{{- $deployment := lower (coalesce (get $env "AGENT_BOM_DEPLOYMENT_ENV") (get $env "AGENT_BOM_ENV") (get $env "ENVIRONMENT") | default "") -}}
{{- $clustered := or (gt (int (include "agent-bom.controlPlaneProcessCapacity" .)) 1) (has (lower (get $env "AGENT_BOM_REQUIRE_SHARED_RATE_LIMIT" | default "")) $truthy) (has $deployment (list "prod" "production")) -}}
{{- $host := "127.0.0.1" -}}
{{- range $index, $arg := $api.args -}}
{{- if and (eq (toString $arg) "--host") (lt (add1 $index) (len $api.args)) -}}
{{- $host = toString (index $api.args (add1 $index)) -}}
{{- end -}}
{{- end -}}
{{- $loopback := has (lower $host) (list "127.0.0.1" "localhost" "::1") -}}
{{- $trustedProxy := and (has (lower (get $env "AGENT_BOM_TRUST_PROXY_AUTH" | default "")) $truthy) (or (hasKey $env "AGENT_BOM_TRUST_PROXY_AUTH_SECRET") (hasKey $env "AGENT_BOM_TRUST_PROXY_AUTH_SECRET_FILE")) (hasKey $env "AGENT_BOM_TRUST_PROXY_AUTH_ISSUER") -}}
{{- $mtls := and (hasKey $env "AGENT_BOM_TLS_CERT_FILE") (hasKey $env "AGENT_BOM_TLS_KEY_FILE") (hasKey $env "AGENT_BOM_TLS_CLIENT_CA_FILE") (has (lower (get $env "AGENT_BOM_TLS_REQUIRE_CLIENT_CERT" | default "")) $truthy) -}}
{{- if and $attestation.fromSecret (not $api.envFrom) -}}
{{- fail "controlPlane.api.listenerAttestation.fromSecret requires a Secret in controlPlane.api.envFrom that supplies the attestation variables" -}}
{{- end -}}
{{- if and $clustered (not $loopback) (not $trustedProxy) (not $mtls) (not $attestation.fromSecret) -}}
{{- fail (printf "a clustered or production API listening on %s refuses to start without request attestation. Set AGENT_BOM_TRUST_PROXY_AUTH=1 with AGENT_BOM_TRUST_PROXY_AUTH_SECRET (at least 32 bytes) and AGENT_BOM_TRUST_PROXY_AUTH_ISSUER, or app-native mTLS (AGENT_BOM_TLS_CERT_FILE, AGENT_BOM_TLS_KEY_FILE, AGENT_BOM_TLS_CLIENT_CA_FILE, AGENT_BOM_TLS_REQUIRE_CLIENT_CERT=1), in controlPlane.api.env; or set controlPlane.api.listenerAttestation.fromSecret=true when a Secret in controlPlane.api.envFrom supplies them" $host) -}}
{{- end -}}
{{- end -}}

{{/*
Postgres role connection demand: every API and worker process at its
configured capacity plus the 25% rolling-update surge, each holding full pools.
Per process, agent_bom_app: the main pool, the admission and idempotency pools
(4 each) and up to 4 graph-build connections; agent_bom_maintenance: a pool of
4. Headroom covers the post-install verification Job and operator sessions.
tests/test_helm_postgres_connection_budget.py keeps this in step with the code.
*/}}
{{- define "agent-bom.postgresConnectionLimits" -}}
{{- $cp := .Values.controlPlane -}}
{{- $poolMax := int $cp.postgres.pool.maxSize -}}
{{- $small := min 4 $poolMax -}}
{{- $processes := 0 -}}
{{- $workloads := list $cp.api -}}
{{- if ($cp.worker | default dict).enabled -}}
{{- $workloads = append $workloads $cp.worker -}}
{{- end -}}
{{- range $workload := $workloads -}}
{{- $capacity := int (include "agent-bom.controlPlaneReplicaCapacity" $workload) -}}
{{- $processes = add $processes $capacity (div (add $capacity 3) 4) -}}
{{- end -}}
{{- $demand := dict "app" (add (mul $processes (add $poolMax $small $small 4)) 5) "maintenance" (add (mul $processes $small) 4) -}}
{{- $configured := $cp.postgres.connectionLimits | default dict -}}
{{- $limits := dict -}}
{{- range $role := list "app" "maintenance" -}}
{{- $need := int (get $demand $role) -}}
{{- $set := int (get $configured $role | default 0) -}}
{{- if and (gt $set 0) (lt $set $need) -}}
{{- fail (printf "controlPlane.postgres.connectionLimits.%s=%d is below the %d connections %d API and worker processes can open during a rolling update (controlPlane.postgres.pool.maxSize=%d); raise it, or set 0 to derive it" $role $set $need $processes $poolMax) -}}
{{- end -}}
{{- $_ := set $limits $role (ternary $set $need (gt $set 0)) -}}
{{- end -}}
{{- toJson $limits -}}
{{- end -}}

{{- define "agent-bom.controlPlaneApiDeployment" -}}
{{- $root := .root -}}
{{- $component := .component -}}
{{- $cp := $root.Values.controlPlane -}}
{{- $api := $cp.api -}}
{{- $worker := $cp.worker | default dict -}}
{{- $isWorker := eq $component "worker" -}}
{{- $workload := ternary $worker $api $isWorker -}}
{{- $postgresSecrets := $cp.postgresSecrets -}}
{{- $nodeSelector := $root.Values.nodeSelector -}}
{{- $tolerations := $root.Values.tolerations -}}
{{- if $isWorker -}}
{{- $nodeSelector = $worker.nodeSelector | default $root.Values.nodeSelector -}}
{{- $tolerations = $worker.tolerations | default $root.Values.tolerations -}}
{{- end -}}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "agent-bom.name" $root }}-{{ $component }}
  namespace: {{ $root.Release.Namespace }}
  labels:
    {{- include "agent-bom.labels" $root | nindent 4 }}
    app.kubernetes.io/component: {{ $component }}
spec:
  replicas: {{ $workload.replicas }}
  selector:
    matchLabels:
      app.kubernetes.io/name: {{ include "agent-bom.name" $root }}
      app.kubernetes.io/component: {{ $component }}
  template:
    metadata:
      labels:
        {{- include "agent-bom.labels" $root | nindent 8 }}
        app.kubernetes.io/component: {{ $component }}
      {{- with $root.Values.podAnnotations }}
      annotations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
    spec:
      {{- if $api.serviceAccount.create }}
      serviceAccountName: {{ include "agent-bom.controlPlaneApiServiceAccountName" $root }}
      automountServiceAccountToken: {{ $api.serviceAccount.automountServiceAccountToken }}
      {{- else }}
      automountServiceAccountToken: false
      {{- end }}
      terminationGracePeriodSeconds: {{ $workload.terminationGracePeriodSeconds | default $api.terminationGracePeriodSeconds | default 30 }}
      {{- $priorityClassName := include "agent-bom.controlPlanePriorityClassName" $root }}
      {{- if $priorityClassName }}
      priorityClassName: {{ $priorityClassName }}
      {{- end }}
      {{- with $root.Values.imagePullSecrets }}
      imagePullSecrets:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      securityContext:
        {{- toYaml $root.Values.podSecurityContext | nindent 8 }}
      {{- include "agent-bom.controlPlaneTopologySpreadConstraints" (dict "Values" $root.Values "component" $component "Chart" $root.Chart "Release" $root.Release) | nindent 6 }}
      {{- if and $isWorker $worker.affinity }}
      affinity:
        {{- toYaml $worker.affinity | nindent 8 }}
      {{- else }}
      {{- include "agent-bom.controlPlaneAffinity" (dict "Values" $root.Values "component" $component "Chart" $root.Chart "Release" $root.Release) | nindent 6 }}
      {{- end }}
      containers:
        - name: {{ $component }}
          image: "{{ $root.Values.image.repository }}:{{ $root.Values.image.tag }}"
          imagePullPolicy: {{ $root.Values.image.pullPolicy }}
          args:
            {{- range $api.args }}
            - {{ . | quote }}
            {{- end }}
          ports:
            - containerPort: {{ $api.port }}
              name: http
              protocol: TCP
          env:
            - name: AGENT_BOM_CONTROL_PLANE_REPLICAS
              value: {{ include "agent-bom.controlPlaneProcessCapacity" $root | quote }}
            {{- if $worker.enabled }}
            - name: AGENT_BOM_API_ROLE
              value: {{ $component | quote }}
            - name: AGENT_BOM_DISTRIBUTED_SCANS
              value: "1"
            {{- end }}
            {{- if $cp.connectionsScheduler.enabled }}
            - name: AGENT_BOM_CONNECTIONS_SCHEDULER
              value: "1"
            {{- with $cp.connectionsScheduler.maxConcurrency }}
            - name: AGENT_BOM_CONNECTIONS_SCHEDULER_MAX_CONCURRENCY
              value: {{ . | quote }}
            {{- end }}
            {{- with $cp.connectionsScheduler.pollSeconds }}
            - name: AGENT_BOM_CONNECTIONS_SCHEDULER_POLL_SECONDS
              value: {{ . | quote }}
            {{- end }}
            {{- end }}
            - name: AGENT_BOM_POSTGRES_POOL_MIN_SIZE
              value: {{ $cp.postgres.pool.minSize | quote }}
            - name: AGENT_BOM_POSTGRES_POOL_MAX_SIZE
              value: {{ $cp.postgres.pool.maxSize | quote }}
            - name: AGENT_BOM_GRACEFUL_SHUTDOWN_SECONDS
              value: {{ $api.shutdown.gracefulShutdownSeconds | quote }}
            - name: AGENT_BOM_SHUTDOWN_DRAIN_SECONDS
              value: {{ $api.shutdown.drainSeconds | quote }}
            - name: AGENT_BOM_GRAPH_AUTO_CORRELATE
              value: {{ $cp.autoCorrelation.enabled | quote }}
            - name: AGENT_BOM_GRAPH_AUTO_CORRELATE_MAX_AGE_HOURS
              value: {{ $cp.autoCorrelation.maxAgeHours | quote }}
            {{- if (($cp.logging).json) }}
            - name: AGENT_BOM_LOG_JSON
              value: "1"
            {{- end }}
            {{- include "agent-bom.nvdApiKeyEnv" $root | nindent 12 }}
          {{- $trustedProxy := $api.trustedProxy | default dict }}
          {{- if $trustedProxy.fromSecret }}
            {{- range $name := list "AGENT_BOM_TRUSTED_PROXY_HOPS" "AGENT_BOM_TRUSTED_PROXY_CIDRS" }}
            - name: {{ $name }}
              valueFrom:
                secretKeyRef:
                  name: {{ $trustedProxy.secretName | quote }}
                  key: {{ $name }}
            {{- end }}
          {{- else if and $trustedProxy.hops $trustedProxy.cidrs }}
            - name: AGENT_BOM_TRUSTED_PROXY_HOPS
              value: {{ $trustedProxy.hops | quote }}
            - name: AGENT_BOM_TRUSTED_PROXY_CIDRS
              value: {{ join "," $trustedProxy.cidrs | quote }}
          {{- end }}
          {{- with $api.env }}
            {{- toYaml . | nindent 12 }}
          {{- end }}
          {{- if $isWorker }}
          {{- with $worker.extraEnv }}
            {{- toYaml . | nindent 12 }}
          {{- end }}
          {{- end }}
            {{- if $postgresSecrets.enabled }}
            - name: AGENT_BOM_POSTGRES_PROVIDER
              value: {{ $cp.postgres.provider | quote }}
            - name: AGENT_BOM_POSTGRES_URL
              valueFrom:
                secretKeyRef:
                  name: {{ $postgresSecrets.appSecretRef.name | quote }}
                  key: AGENT_BOM_POSTGRES_URL
            - name: AGENT_BOM_POSTGRES_MAINTENANCE_URL
              valueFrom:
                secretKeyRef:
                  name: {{ $postgresSecrets.maintenanceSecretRef.name | quote }}
                  key: AGENT_BOM_POSTGRES_MAINTENANCE_URL
            {{- end }}
          {{- with $api.envFrom }}
          envFrom:
            {{- toYaml . | nindent 12 }}
          {{- end }}
          securityContext:
            {{- toYaml $root.Values.securityContext | nindent 12 }}
          volumeMounts:
            - name: tmp
              mountPath: /tmp
            {{- with $api.extraVolumeMounts }}
            {{- toYaml . | nindent 12 }}
            {{- end }}
          {{- if and (not $isWorker) (gt (int $api.shutdown.preStopSleepSeconds) 0) }}
          lifecycle:
            preStop:
              exec:
                command: ["sleep", {{ $api.shutdown.preStopSleepSeconds | quote }}]
          {{- end }}
          resources:
            {{- toYaml ($workload.resources | default $api.resources) | nindent 12 }}
          livenessProbe:
            {{- toYaml $api.livenessProbe | nindent 12 }}
          readinessProbe:
            {{- toYaml $api.readinessProbe | nindent 12 }}
          startupProbe:
            {{- toYaml $api.startupProbe | nindent 12 }}
      {{- with $nodeSelector }}
      nodeSelector:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with $tolerations }}
      tolerations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      volumes:
        - name: tmp
          emptyDir: {}
        {{- with $api.extraVolumes }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
{{- end }}
